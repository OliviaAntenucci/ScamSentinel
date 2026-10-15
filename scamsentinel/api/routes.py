"""HTTP routes (prd.txt §8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Path, Query, Request, Response
from starlette.concurrency import run_in_threadpool

from scamsentinel import __version__
from scamsentinel.accounts import hash_password, new_session_token, verify_password
from scamsentinel.api.guards import auth_rate_limited, rate_limited, require_local_post
from scamsentinel.api.schemas import AccountRequest, AnalyzeRequest
from scamsentinel.ct.store import CtCandidateList, CtStore
from scamsentinel.domain.engine import DomainResult, get_engine
from scamsentinel.domain.normalize import InvalidHost
from scamsentinel.models import AnalysisResult
from scamsentinel.ocr.vision import OcrUnavailable
from scamsentinel.pipeline import AnalysisService, NoTextFound
from scamsentinel.security.upload_guard import UploadRejected

router = APIRouter()

ANALYSIS_ID_PATTERN = r"^an_[0-9a-f]{32}$"
SESSION_COOKIE = "scamsentinel_session"


def _service(request: Request) -> AnalysisService:
    return request.app.state.service


def _account(
    request: Request, token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None
) -> tuple[int, str] | None:
    if token is None:
        return None
    return request.app.state.account_store.get_session_account(token)


Account = tuple[int, str]
CurrentAccount = Annotated[Account | None, Depends(_account)]


def _required_account(account: CurrentAccount) -> Account:
    if account is None:
        raise HTTPException(status_code=401, detail="log in to access saved analyses")
    return account


AuthenticatedAccount = Annotated[Account, Depends(_required_account)]


def _set_session(response: Response, request: Request, account_id: int) -> None:
    token = new_session_token()
    request.app.state.account_store.create_account_session(
        token, account_id, datetime.now(UTC) + timedelta(days=30)
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=30 * 24 * 60 * 60,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )


@router.post(
    "/v1/auth/register",
    dependencies=[
        Depends(require_local_post("application/json")),
        Depends(auth_rate_limited),
    ],
)
def register(request: Request, body: AccountRequest, response: Response) -> dict[str, str]:
    email = body.email.strip().lower()
    account_id = request.app.state.account_store.create_account(email, hash_password(body.password))
    if account_id is None:
        raise HTTPException(status_code=409, detail="an account with that email already exists")
    _set_session(response, request, account_id)
    return {"email": email}


@router.post(
    "/v1/auth/login",
    dependencies=[
        Depends(require_local_post("application/json")),
        Depends(auth_rate_limited),
    ],
)
def login(request: Request, body: AccountRequest, response: Response) -> dict[str, str]:
    email = body.email.strip().lower()
    credentials = request.app.state.account_store.get_account_credentials(email)
    if credentials is None or not verify_password(body.password, credentials[1]):
        raise HTTPException(status_code=401, detail="email or password is incorrect")
    _set_session(response, request, credentials[0])
    return {"email": email}


@router.get("/v1/auth/me")
def auth_me(account: CurrentAccount) -> dict[str, str | None]:
    return {"email": account[1] if account else None}


@router.post(
    "/v1/auth/logout",
    dependencies=[Depends(require_local_post("application/json"))],
)
def logout(
    request: Request,
    response: Response,
    token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict[str, str]:
    if token:
        request.app.state.account_store.delete_account_session(token)
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    return {"status": "ok"}


@router.get("/v1/saved")
def list_saved_analyses(request: Request, account: AuthenticatedAccount):
    return request.app.state.account_store.list_account_analyses(account[0])


@router.post(
    "/v1/saved/{analysis_id}",
    dependencies=[Depends(require_local_post("application/json"))],
)
def save_analysis(
    request: Request,
    analysis_id: Annotated[str, Path(pattern=ANALYSIS_ID_PATTERN)],
    account: AuthenticatedAccount,
) -> dict[str, str]:
    result = request.app.state.account_store.get_account_analysis(account[0], analysis_id)
    if result is not None:
        return {"analysis_id": analysis_id}
    result = _service(request).get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="analysis not found or expired")
    request.app.state.account_store.save_account_analysis(account[0], result)
    return {"analysis_id": analysis_id}


@router.delete("/v1/saved/{analysis_id}")
def delete_saved_analysis(
    request: Request,
    analysis_id: Annotated[str, Path(pattern=ANALYSIS_ID_PATTERN)],
    account: AuthenticatedAccount,
) -> dict[str, str]:
    if not request.app.state.account_store.delete_account_analysis(account[0], analysis_id):
        raise HTTPException(status_code=404, detail="saved analysis not found")
    return {"status": "deleted"}


@router.get("/v1/saved/{analysis_id}")
def get_saved_analysis(
    request: Request,
    analysis_id: Annotated[str, Path(pattern=ANALYSIS_ID_PATTERN)],
    account: AuthenticatedAccount,
):
    result = request.app.state.account_store.get_account_analysis(account[0], analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="saved analysis not found")
    return result


@router.get("/healthz")
def healthz(request: Request) -> dict[str, str]:
    settings = request.app.state.settings
    groq_key = settings.groq_api_key
    return {
        "status": "ok",
        "version": __version__,
        "llm_provider": settings.llm_provider,
        "llm_model": settings.resolved_llm_model,
        "llm": "configured" if settings.llm_api_key else "missing_api_key (rules-only)",
        "org_fact_check": (
            "off"
            if not settings.org_fact_check
            else "available (unverified LLM knowledge, risk-only)"
            if settings.llm_api_key and settings.llm_provider == "groq"
            else "unavailable (needs GROQ_API_KEY)"
        ),
        "vision_model": settings.vision_model,
        "screenshots": (
            "available"
            if groq_key and groq_key.get_secret_value().strip()
            else "unavailable (needs GROQ_API_KEY)"
        ),
    }


@router.post(
    "/v1/analyze",
    dependencies=[Depends(require_local_post("application/json")), Depends(rate_limited)],
)
def analyze(request: Request, body: AnalyzeRequest) -> AnalysisResult:
    try:
        return _service(request).analyze(body)
    except InvalidHost as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# Raw image bodies. None of these are CORS "simple" content types, so a web page on
# another origin can't send them without a preflight (which this API never approves).
IMAGE_CONTENT_TYPES = ("image/png", "image/jpeg", "image/webp", "application/octet-stream")


@router.post(
    "/v1/analyze/image",
    dependencies=[Depends(require_local_post(*IMAGE_CONTENT_TYPES)), Depends(rate_limited)],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                t: {"schema": {"type": "string", "format": "binary"}} for t in IMAGE_CONTENT_TYPES
            },
        }
    },
)
async def analyze_image(request: Request) -> AnalysisResult:
    """Analyze a screenshot sent as the raw request body (PNG, JPEG or WebP, max 5 MB)."""
    data = await request.body()
    try:
        return await run_in_threadpool(_service(request).analyze_image, data)
    except UploadRejected as exc:
        status = 413 if exc.reason == "too_large" else 422
        raise HTTPException(status_code=status, detail=f"image rejected: {exc}") from exc
    except OcrUnavailable as exc:
        raise HTTPException(
            status_code=503, detail=f"screenshot analysis unavailable: {exc.reason}"
        ) from exc
    except NoTextFound as exc:
        raise HTTPException(status_code=422, detail="no readable text found in the image") from exc


@router.get("/v1/analysis/{analysis_id}")
def get_analysis(
    request: Request, analysis_id: Annotated[str, Path(pattern=ANALYSIS_ID_PATTERN)]
) -> AnalysisResult:
    result = _service(request).get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="analysis not found or expired")
    return result


@router.get("/v1/domain/score")
def domain_score(
    request: Request, d: Annotated[str, Query(min_length=1, max_length=2_048)]
) -> DomainResult:
    settings = request.app.state.settings
    try:
        return get_engine(settings.data_dir, settings.config_dir).score(d)
    except InvalidHost as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/v1/ct/candidates")
def ct_candidates(
    request: Request,
    since: Annotated[datetime | None, Query(description="first seen at or after (UTC)")] = None,
    min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
) -> CtCandidateList:
    """Lookalike domains found in Certificate Transparency logs by the CT watcher
    (`python -m scamsentinel.ct`). These are unverified leads; none of them was visited."""
    store: CtStore = request.app.state.ct_store
    if min_score is None:
        min_score = request.app.state.settings.ct_min_score
    candidates = store.list_candidates(since=since, min_score=min_score, limit=limit)
    return CtCandidateList(
        last_poll=store.last_poll(), count=len(candidates), candidates=candidates
    )
