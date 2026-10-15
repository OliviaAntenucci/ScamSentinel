"""Run samples through the real AnalysisService and collect predictions."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from scamsentinel.api.schemas import AnalyzeRequest
from scamsentinel.config import Settings
from scamsentinel.data import load_brands, load_facts, load_keywords, load_scoring
from scamsentinel.domain.engine import get_engine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.eval.dataset import Sample
from scamsentinel.eval.metrics import Prediction
from scamsentinel.message.analyzer import MessageAnalyzer
from scamsentinel.message.llm import CachedExtractor, build_extractor
from scamsentinel.models import Verdict
from scamsentinel.pipeline import AnalysisService
from scamsentinel.store import Store

Ablation = Literal["full", "rules_only", "no_verify"]
_FIELD = {"text": "text", "url": "url", "email": "email_raw"}


def build_service(settings: Settings, ablation: Ablation, db_path: Path) -> AnalysisService:
    """The production pipeline, optionally with parts switched off.

    - full: rules + LLM (if a key is configured) + verification
    - rules_only: no LLM
    - no_verify: verification checks contribute 0 points
    The LLM cache lives in `db_path`, so re-running an evaluation doesn't re-call the LLM.
    """
    store = Store(db_path, settings.retention_days)
    scoring = load_scoring(settings.config_dir)
    if ablation == "no_verify":
        scoring = scoring.model_copy(
            update={"verify_points": {k: 0 for k in scoring.verify_points}}
        )

    llm = None
    if ablation != "rules_only":
        built = build_extractor(settings)
        if built is not None:
            llm = CachedExtractor(built, store, settings.llm_provider, settings.resolved_llm_model)

    engine = get_engine(settings.data_dir, settings.config_dir)
    analyzer = MessageAnalyzer(
        keywords=load_keywords(settings.data_dir),
        brands=load_brands(settings.data_dir),
        facts=load_facts(settings.data_dir),
        engine=engine,
        message_points=scoring.message_points,
        verify_points=scoring.verify_points,
        llm=llm,
        max_chars=settings.max_text_chars,
    )
    return AnalysisService(engine=engine, analyzer=analyzer, scoring=scoring, store=store)


def run(samples: list[Sample], service: AnalysisService) -> list[Prediction]:
    predictions = []
    for sample in samples:
        common = {
            "id": sample.id,
            "input_type": sample.input_type,
            "label": sample.label,
            "brand": sample.brand,
            "synthetic": sample.synthetic,
        }
        request = AnalyzeRequest(**{_FIELD[sample.input_type]: sample.content})
        try:
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
            )
        )
    return predictions
