"""Analysis orchestrator: ingest -> domain/message -> verify -> aggregate -> store (M3).

MVP rule: URLs are only analyzed as strings. The pipeline never connects to a
user-supplied URL, which removes SSRF by design (SECURITY.md T1).
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
from scamsentinel.message.llm import CachedExtractor, FeatureExtractor, build_extractor
from scamsentinel.models import AnalysisResult, InputType
from scamsentinel.security.redaction import redact_result
from scamsentinel.store import Store

logger = logging.getLogger(__name__)

# Upper bound on domains scored per input, so a message stuffed with links stays cheap.
MAX_DOMAINS = 20


class AnalysisService:
    def __init__(
        self,
        *,
        engine: DomainEngine,
        analyzer: MessageAnalyzer,
        scoring: ScoringConfig,
        store: Store,
    ) -> None:
        self._engine = engine
        self._analyzer = analyzer
        self._scoring = scoring
        self._store = store

    @classmethod
    def from_settings(
        cls, settings: Settings, llm: FeatureExtractor | None = None
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
        )

    def analyze(self, request: AnalyzeRequest) -> AnalysisResult:
        """Analyze one input. Raises InvalidHost if a submitted URL has no usable host."""
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
        self._store.save_analysis(analysis, hashlib.sha256(raw.encode()).hexdigest())
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

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        return self._store.get_analysis(analysis_id)

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
