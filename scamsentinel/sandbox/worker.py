"""Internal HTTP worker inside the sandbox container. Reachable only from the API
over the internal `sandbox_ctl` network."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from scamsentinel.api.errors import install_error_handlers
from scamsentinel.sandbox.detonator import SandboxReport, detonate

app = FastAPI(title="ScamSentinel sandbox worker", docs_url=None, redoc_url=None)
install_error_handlers(app)


class DetonationJob(BaseModel):
    analysis_id: str
    url: str = Field(max_length=2_048)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/detonate")
def detonate_job(job: DetonationJob) -> SandboxReport:
    return detonate(job.url)
