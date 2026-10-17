"""Analysis orchestrator: ingest -> domain/message -> verify -> aggregate -> store.

By default URLs are only analyzed as strings: the pipeline never connects to a
user-supplied URL, which removes SSRF by design (SECURITY.md T1), and the only outbound
calls go to the configured LLM provider (feature extraction, screenshot transcription,
and the fact check for organizations without curated facts). With page fetching set to
"live" (P2, SCAMSENTINEL_PAGE_FETCH; "off" by default, "dry_run" never connects), the
first few non-official links are also fetched, only through the SSRF guard
(security/url_guard.py) and the egress lock (security/egress.py).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from scamsentinel.aggregate.aggregator import MAX_DOMAINS_IN_REASONS, aggregate
from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.config import Settings
from scamsentinel.data import ScoringConfig, load_brands, load_keywords, load_scoring
from scamsentinel.domain.engine import DomainEngine, DomainResult, get_engine
from scamsentinel.domain.explain import DomainExplanation
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.guidance.next_steps import NextStepsGuide
from scamsentinel.ingest.email import parse_eml
from scamsentinel.ingest.urls import refang
from scamsentinel.message.analyzer import MessageAnalysis, MessageAnalyzer
from scamsentinel.message.llm import (
    CachedExtractor,
    FeatureExtractor,
    LlmUnavailable,
    build_extractor,
)
from scamsentinel.models import AnalysisResult, InputType, Module, PageReport, Reason
from scamsentinel.ocr.vision import OcrUnavailable, Transcriber, build_transcriber
from scamsentinel.page.analyze import PageAnalyzer
from scamsentinel.page.fetch import PageFetcher, PageSource
from scamsentinel.page.score import page_module
from scamsentinel.security.image_sanitize import sanitize_image
from scamsentinel.security.redaction import redact_result
from scamsentinel.security.upload_guard import validate_image_upload
from scamsentinel.store import Store
from scamsentinel.verify.checks import fact_checks
from scamsentinel.verify.org_facts import OrgFactChecker, build_org_fact_checker

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
        guide: NextStepsGuide | None = None,
        page_fetcher: PageSource | None = None,
        page_analyzer: PageAnalyzer | None = None,
        max_page_links: int = 3,
    ) -> None:
        self._guide = guide
        # P2: both None unless page fetching was turned on (or, in evaluation, snapshots).
        self._page_fetcher = page_fetcher
        self._page_analyzer = page_analyzer
        self._max_page_links = max_page_links
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
        org_facts: OrgFactChecker | None = None,
    ) -> AnalysisService:
        store = Store(settings.db_path, settings.retention_days)
        if org_facts is None:
            org_facts = build_org_fact_checker(settings, store)
        if llm is None:
            built = build_extractor(settings)
            llm = (
                CachedExtractor(built, store, settings.llm_provider, settings.resolved_llm_model)
                if built is not None
                else None
            )
        engine = get_engine(settings.data_dir, settings.config_dir)
        page_fetcher = page_analyzer = None
        if settings.page_fetch != "off":
            page_fetcher = PageFetcher(
                mode=settings.page_fetch,
                max_per_minute=settings.page_fetch_max_per_minute,
                timeout=settings.page_fetch_timeout_seconds,
                max_bytes=settings.page_fetch_max_bytes,
                max_redirects=settings.page_fetch_max_redirects,
                allow_private=settings.allow_private_targets,
            )
            page_analyzer = PageAnalyzer(
                load_brands(settings.data_dir),
                load_keywords(settings.data_dir).entity_mentions,
                engine,
            )
        return cls(
            engine=engine,
            analyzer=MessageAnalyzer.from_settings(settings, llm=llm, org_facts=org_facts),
            scoring=load_scoring(settings.config_dir),
            store=store,
            transcriber=transcriber or build_transcriber(settings, store),
            max_image_bytes=settings.max_image_bytes,
            max_image_pixels=settings.max_image_pixels,
            max_text_chars=settings.max_text_chars,
            guide=NextStepsGuide.from_files(settings.data_dir),
            page_fetcher=page_fetcher,
            page_analyzer=page_analyzer,
            max_page_links=settings.page_fetch_max_links,
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
        # Links whose pages may be inspected (P2): the submitted URL, or the message's own
        # links. Never the email's sender domains.
        links = [refang(raw.strip())] if message is None else message.features.claimed_urls
        return self._finish(input_type, raw.encode(), message, domains, links)

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
        return self._finish("image", data, message, domains, message.features.claimed_urls)

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        return self._store.get_analysis(analysis_id)

    def _finish(
        self,
        input_type: InputType,
        raw: bytes,
        message: MessageAnalysis | None,
        domains: list[DomainResult],
        links: list[str] | None = None,
    ) -> AnalysisResult:
        # P2b: linked pages (live, or snapshots in evaluation) are read before scoring.
        # Nothing happens here unless page fetching is on.
        pages = self._inspect_pages(links or [])
        domains = self._with_page_destinations(domains, pages)
        result = aggregate(
            domains=domains,
            message=message.result if message else None,
            features=message.features if message else None,
            config=self._scoring,
            checks=message.checks if message else None,
            page=page_module(pages, self._scoring.page_points) if pages else None,
            page_reports=pages,
        )
        # A brand the page presents itself as lets the guidance name it (risk-only: it
        # never lowers a score, and it's only used when nothing else names a brand).
        page_brand = next((p.brand for p in pages if p.brand), None)
        # Named scenario (E4): explains the result, never changes it.
        scenario = (
            self._guide.scenario(
                verdict=result.verdict,
                features=message.features,
                domains=domains,
                text=message.text,
                page_brand=page_brand,
            )
            if self._guide and message
            else None
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
            next_steps=(
                self._guide.build(
                    verdict=result.verdict,
                    input_type=input_type,
                    features=message.features if message else None,
                    domains=domains,
                    checks=message.checks if message else [],
                    scenario=scenario,
                    page_brand=page_brand,
                )
                if self._guide
                else []
            ),
            domain_explanations=_explanations(domains),
            fact_checks=fact_checks(message.checks) if message else [],
            scenario=scenario,
            resources=(
                self._guide.resources(
                    verdict=result.verdict,
                    features=message.features if message else None,
                    domains=domains,
                    scenario=scenario,
                    page_brand=page_brand,
                )
                if self._guide
                else []
            ),
            pages=pages,
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

    def _inspect_pages(self, links: list[str]) -> list[PageReport]:
        """Fetch and read the first few non-official links (P2). Off unless enabled."""
        if self._page_fetcher is None or self._page_analyzer is None:
            return []
        reports: list[PageReport] = []
        seen: set[str] = set()
        for link in links:
            if len(reports) >= self._max_page_links:
                break
            try:
                domain = self._engine.score(link)
            except InvalidHost:
                continue
            if domain.official or domain.host in seen:
                continue  # an official site isn't the scam page; one fetch per host
            seen.add(domain.host)
            url = link if "://" in link else f"https://{link}"
            try:
                reports.append(self._page_analyzer.analyze(self._page_fetcher.fetch(url)))
            except Exception:  # fail closed: a page problem never breaks the analysis
                logger.exception("page inspection failed")
                reports.append(
                    PageReport(requested_url=url, status="failed", error="internal_error")
                )
        return reports

    def _with_page_destinations(
        self, domains: list[DomainResult], pages: list[PageReport]
    ) -> list[DomainResult]:
        """Where a link's redirects ended up is scored like any other link (P2b): a
        shortener that lands on a lookalike counts as that lookalike."""
        hosts = {d.host for d in domains}
        extra: list[DomainResult] = []
        for page in pages:
            if not page.redirects or not page.final_url:
                continue
            try:
                result = self._engine.score(page.final_url)
            except InvalidHost:
                continue
            if result.host not in hosts:
                hosts.add(result.host)
                extra.append(result)
        return [*domains, *extra]

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


def _explanations(domains: list[DomainResult]) -> list[DomainExplanation]:
    """One explanation per lookalike registrable domain, highest score first (E2)."""
    explained: dict[str, DomainExplanation] = {}
    for d in sorted(domains, key=lambda d: d.score, reverse=True):
        if d.explanation is not None and d.registrable not in explained:
            explained[d.registrable] = d.explanation
    return list(explained.values())[:MAX_DOMAINS_IN_REASONS]
