"""Analysis orchestrator: ingest -> domain/message -> verify -> aggregate -> store.

MVP rule: URLs are only analyzed as strings. The pipeline never connects to a
user-supplied URL, which removes SSRF by design (SECURITY.md T1). The only outbound
calls go to the configured LLM provider.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from scamsentinel.aggregate.aggregator import aggregate
from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.config import Settings
from scamsentinel.data import ScoringConfig, load_scoring
from scamsentinel.domain.engine import DomainEngine, DomainResult, get_engine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.ingest.email import parse_eml
from scamsentinel.message.analyzer import MessageAnalysis, MessageAnalyzer
from scamsentinel.message.llm import (
    CachedExtractor,
    FeatureExtractor,
    LlmUnavailable,
    build_extractor,
)
from scamsentinel.models import AnalysisResult, InputType, Module, Reason
from scamsentinel.ocr.vision import OcrUnavailable, Transcriber, build_transcriber
from scamsentinel.security.image_sanitize import sanitize_image
from scamsentinel.security.redaction import redact_result
from scamsentinel.security.upload_guard import validate_image_upload
from scamsentinel.store import Store

logger = logging.getLogger(__name__)

# Upper bound on domains scored per input, so a message stuffed with links stays cheap.
MAX_DOMAINS = 20


class NoTextFound(Exception):
    """The screenshot was read, but it contains no text to analyze."""


class AnalysisService:
    def __init__(
        self,
        *,
        engine: DomainEngine,
        analyzer: MessageAnalyzer,
        scoring: ScoringConfig,
        store: Store,
        transcriber: Transcriber | None = None,
        max_image_bytes: int = 5 * 1024 * 1024,
        max_image_pixels: int = 25_000_000,
        max_text_chars: int = 20_000,
    ) -> None:
        self._engine = engine
        self._analyzer = analyzer
        self._scoring = scoring
        self._store = store
        self._transcriber = transcriber
        self._max_image_bytes = max_image_bytes
        self._max_image_pixels = max_image_pixels
        self._max_text_chars = max_text_chars

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        llm: FeatureExtractor | None = None,
        transcriber: Transcriber | None = None,
    ) -> AnalysisService:
        store = Store(settings.db_path, settings.retention_days)
        if llm is None:
            built = build_extractor(settings)
            llm = (
                CachedExtractor(built, store, settings.llm_provider, settings.resolved_llm_model)
                if built is not None
                else None
            )
        return cls(
            engine=get_engine(settings.data_dir, settings.config_dir),
            analyzer=MessageAnalyzer.from_settings(settings, llm=llm),
            scoring=load_scoring(settings.config_dir),
            store=store,
            transcriber=transcriber or build_transcriber(settings, store),
            max_image_bytes=settings.max_image_bytes,
            max_image_pixels=settings.max_image_pixels,
            max_text_chars=settings.max_text_chars,
        )

    def analyze(self, request: AnalyzeRequest) -> AnalysisResult:
        """Analyze text, a URL or an email. Raises InvalidHost for an unusable URL input."""
        message: MessageAnalysis | None = None
        input_type: InputType
        if request.text is not None:
            input_type, raw = "text", request.text
            message = self._analyzer.analyze(request.text, input_type="text")
            hosts = message.features.claimed_urls
        elif request.email_raw is not None:
            input_type, raw = "email", request.email_raw
            parsed = parse_eml(request.email_raw.encode("utf-8", errors="replace"))
            message = self._analyzer.analyze(
                parsed.analysis_text(), input_type="email", email=parsed, extra_urls=parsed.links
            )
            senders = [parsed.from_domain, parsed.reply_to_domain]
            hosts = [*message.features.claimed_urls, *(s for s in senders if s)]
        else:
            # A bare URL is scored by the domain engine only; running the message analyzer
            # on the URL string would count the same evidence twice.
            input_type, raw = "url", request.url or ""
            hosts = [raw]

        domains = self._score_domains(hosts, strict=input_type == "url")
        return self._finish(input_type, raw.encode(), message, domains)

    def analyze_image(self, data: bytes) -> AnalysisResult:
        """Analyze a screenshot.

        Raises UploadRejected (bad file), OcrUnavailable (can't read it) or NoTextFound.
        A screenshot that couldn't be read is an error, never a "likely legitimate" verdict.
        """
        info = validate_image_upload(
            data, max_bytes=self._max_image_bytes, max_pixels=self._max_image_pixels
        )
        clean = sanitize_image(data, info.mime)
        if self._transcriber is None:
            raise OcrUnavailable("vision_not_configured")
        try:
            text = self._transcriber.transcribe(clean, info.mime).strip()
        except LlmUnavailable as exc:
            raise OcrUnavailable(exc.reason) from exc
        if not text:
            raise NoTextFound
        text = text[: self._max_text_chars]

        message = self._analyzer.analyze(text, input_type="image")
        transcribed = Reason(
            module=Module.OCR,
            signal="transcribed",
            detail=(
                f"Read {len(text):,} characters from a {info.width}×{info.height} "
                f"{info.mime.removeprefix('image/').upper()} screenshot "
                f"({self._transcriber.model}); metadata was stripped before sending"
            ),
            points=0,
        )
        message.result.reasons.insert(0, transcribed)
        domains = self._score_domains(message.features.claimed_urls, strict=False)
        return self._finish("image", data, message, domains)

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        return self._store.get_analysis(analysis_id)

    def _finish(
        self,
        input_type: InputType,
        raw: bytes,
        message: MessageAnalysis | None,
        domains: list[DomainResult],
    ) -> AnalysisResult:
        result = aggregate(
            domains=domains,
            message=message.result if message else None,
            features=message.features if message else None,
            config=self._scoring,
        )
        analysis = AnalysisResult(
            analysis_id=f"an_{uuid.uuid4().hex}",
            created_at=datetime.now(UTC),
            input_type=input_type,
            verdict=result.verdict,
            risk_score=result.risk_score,
            module_scores=result.module_scores,
            modules_run=result.modules_run,
            llm_used=message.llm_used if message else False,
            degraded=message.degraded if message else [],
            reasons=result.reasons,
            overrides_applied=result.overrides_applied,
            disagreements=message.disagreements if message else [],
        )
        # SSN/card numbers quoted as evidence never reach the response, disk or logs.
        analysis = redact_result(analysis)
        self._store.save_analysis(analysis, hashlib.sha256(raw).hexdigest())
        # Metadata only: the analyzed content is never logged.
        logger.info(
            "analysis %s input=%s verdict=%s score=%d llm=%s degraded=%s",
            analysis.analysis_id,
            input_type,
            analysis.verdict.value,
            analysis.risk_score,
            analysis.llm_used,
            ",".join(analysis.degraded) or "-",
        )
        return analysis

    def _score_domains(self, hosts: list[str], *, strict: bool) -> list[DomainResult]:
        results: list[DomainResult] = []
        seen: set[str] = set()
        for host in hosts[:MAX_DOMAINS]:
            try:
                result = self._engine.score(host)
            except InvalidHost:
                if strict:
                    raise
                continue
            if result.host not in seen:
                seen.add(result.host)
                results.append(result)
        return results
