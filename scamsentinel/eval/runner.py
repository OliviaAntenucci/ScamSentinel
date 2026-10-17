"""Run samples through the real AnalysisService and collect predictions."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.config import Settings
from scamsentinel.data import load_brands, load_facts, load_keywords, load_scoring
from scamsentinel.domain.engine import get_engine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.eval.dataset import Sample
from scamsentinel.eval.metrics import Prediction
from scamsentinel.guidance.next_steps import NextStepsGuide
from scamsentinel.message.analyzer import MessageAnalyzer
from scamsentinel.message.llm import CachedExtractor, build_extractor
from scamsentinel.models import Verdict
from scamsentinel.page.analyze import PageAnalyzer
from scamsentinel.page.snapshots import SnapshotFetcher
from scamsentinel.pipeline import AnalysisService
from scamsentinel.store import Store
from scamsentinel.verify.org_facts import build_org_fact_checker

Ablation = Literal["full", "rules_only", "no_verify"]
PagesMode = Literal["snapshot", "off"]
_FIELD = {"text": "text", "url": "url", "email": "email_raw"}


def build_service(
    settings: Settings,
    ablation: Ablation,
    db_path: Path,
    pages: PagesMode = "off",
    pages_dir: Path | None = None,
) -> AnalysisService:
    """The production pipeline, optionally with parts switched off.

    - full: rules + LLM (if a key is configured) + verification
    - rules_only: no LLM
    - no_verify: verification checks contribute 0 points
    The LLM cache lives in `db_path`, so re-running an evaluation doesn't re-call the LLM.

    pages="snapshot" answers page fetches from the hand-written pages in `pages_dir`
    (data/eval/pages/) and never touches the network; "off" ignores pages (P2b).
    """
    store = Store(db_path, settings.retention_days)
    scoring = load_scoring(settings.config_dir)
    if ablation == "no_verify":
        scoring = scoring.model_copy(
            update={"verify_points": {k: 0 for k in scoring.verify_points}}
        )

    llm = None
    org_facts = None
    if ablation != "rules_only":
        built = build_extractor(settings)
        if built is not None:
            llm = CachedExtractor(built, store, settings.llm_provider, settings.resolved_llm_model)
        org_facts = build_org_fact_checker(settings, store)

    engine = get_engine(settings.data_dir, settings.config_dir)
    analyzer = MessageAnalyzer(
        keywords=load_keywords(settings.data_dir),
        brands=load_brands(settings.data_dir),
        facts=load_facts(settings.data_dir),
        engine=engine,
        message_points=scoring.message_points,
        verify_points=scoring.verify_points,
        llm=llm,
        org_facts=org_facts,
        max_chars=settings.max_text_chars,
    )
    page_fetcher = page_analyzer = None
    if pages == "snapshot":
        page_fetcher = SnapshotFetcher(pages_dir or settings.data_dir / "eval" / "pages")
        page_analyzer = PageAnalyzer(
            load_brands(settings.data_dir),
            load_keywords(settings.data_dir).entity_mentions,
            engine,
        )
    return AnalysisService(
        engine=engine,
        analyzer=analyzer,
        scoring=scoring,
        store=store,
        guide=NextStepsGuide.from_files(settings.data_dir),
        page_fetcher=page_fetcher,
        page_analyzer=page_analyzer,
        max_page_links=settings.page_fetch_max_links,
    )


RATE_LIMITED = "llm_unavailable:rate_limited"


def run(
    samples: list[Sample],
    service: AnalysisService,
    *,
    rate_limit_retries: int = 0,
    rate_limit_wait: float = 20.0,
    sleep: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] | None = None,
    scenario_labels: dict[str, str] | None = None,
) -> list[Prediction]:
    """Analyze each sample. With retries > 0, a sample whose LLM call was rate limited
    (free-tier quotas) is retried after `rate_limit_wait` seconds instead of silently
    being scored rules-only. Successful LLM results are cached, so retries are cheap.
    `scenario_labels` (sample id -> expected scenario) is copied onto each prediction."""
    sample_scenarios = scenario_labels or {}
    predictions = []
    for index, sample in enumerate(samples, 1):
        common = {
            "id": sample.id,
            "input_type": sample.input_type,
            "label": sample.label,
            "brand": sample.brand,
            "category": sample.category,
            "synthetic": sample.synthetic,
            "expected_scenario": sample_scenarios.get(sample.id),
        }
        request = AnalyzeRequest(**{_FIELD[sample.input_type]: sample.content})
        try:
            result = service.analyze(request)
            for attempt in range(1, rate_limit_retries + 1):
                if RATE_LIMITED not in result.degraded:
                    break
                if progress:
                    wait = f"{rate_limit_wait:g}s"
                    progress(f"  {sample.id}: rate limited, retry {attempt} in {wait}")
                sleep(rate_limit_wait)
                result = service.analyze(request)
        except InvalidHost as exc:
            # Counted as "not flagged", and listed in the report so it's visible.
            predictions.append(
                Prediction(
                    **common, verdict=Verdict.LIKELY_LEGITIMATE, risk_score=0, error=str(exc)
                )
            )
            continue
        predictions.append(
            Prediction(
                **common,
                verdict=result.verdict,
                risk_score=result.risk_score,
                signals=[r.signal for r in result.reasons if r.points != 0],
                llm_used=result.llm_used,
                degraded=result.degraded,
                scenario=result.scenario.id if result.scenario else None,
            )
        )
        if progress and index % 10 == 0:
            progress(f"  {index}/{len(samples)} samples")
    return predictions
