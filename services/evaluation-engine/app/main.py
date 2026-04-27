import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from requests import RequestException
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from app.client import fetch_latest_telemetry, fetch_policies, forward_decision
from app.db import Base, engine, get_db
from app.evaluators import build_registry
from app.models import EvaluationResultModel
from app.service import evaluate_telemetry
from posture_shared.models.evaluation import ComplianceDecision
from posture_shared.models.policy import PosturePolicy
from posture_shared.models.telemetry import EndpointTelemetry
from posture_shared.security import parse_cors_origins, require_api_key


Base.metadata.create_all(bind=engine)


def ensure_performance_indexes() -> None:
    statements = [
        "CREATE INDEX IF NOT EXISTS idx_evaluation_results_endpoint_created ON evaluation_results(endpoint_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_evaluation_results_policy_created ON evaluation_results(policy_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_evaluation_results_endpoint_policy_created ON evaluation_results(endpoint_id, policy_id, created_at DESC)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


ensure_performance_indexes()

app = FastAPI(title="evaluation-engine", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1200, compresslevel=6)
registry = build_registry()
logger = logging.getLogger("evaluation-engine")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
EVALUATION_RATE_LIMIT_PER_MINUTE = int(os.getenv("EVALUATION_RATE_LIMIT_PER_MINUTE", "600"))
_evaluation_rate_lock = threading.Lock()
_evaluation_rate_state: dict[str, list[float]] = {}


def _apply_evaluation_rate_limit(identity: str) -> None:
    now = time.monotonic()
    with _evaluation_rate_lock:
        history = _evaluation_rate_state.setdefault(identity, [])
        history[:] = [item for item in history if now - item <= 60.0]
        if len(history) >= EVALUATION_RATE_LIMIT_PER_MINUTE:
            raise HTTPException(status_code=429, detail="Too many evaluation requests")
        history.append(now)


class InlineEvaluationRequest(BaseModel):
    telemetry: EndpointTelemetry
    policy: PosturePolicy | None = None


def persist_evaluation_result(decision: ComplianceDecision, db: Session) -> None:
    result = EvaluationResultModel(
        endpoint_id=decision.endpoint_id,
        policy_id=decision.policy_id,
        policy_name=decision.policy_name,
        compliant=decision.compliant,
        recommended_action=decision.recommended_action,
        reasons=[reason.model_dump(mode="json") for reason in decision.reasons],
        raw_result=decision.model_dump(mode="json"),
    )
    db.add(result)


def forward_decisions(decisions: list[ComplianceDecision]) -> None:
    for decision in decisions:
        try:
            forward_decision(decision)
        except RequestException as exc:
            logger.warning(
                "failed to forward decision endpoint_id=%s policy_id=%s error=%s",
                decision.endpoint_id,
                decision.policy_id,
                exc,
            )


def evaluate_and_store_decisions(
    telemetry: EndpointTelemetry,
    policies: list[PosturePolicy],
    db: Session,
) -> list[ComplianceDecision]:
    if not policies:
        decisions = [evaluate_telemetry(telemetry, None, registry)]
    else:
        decisions = [evaluate_telemetry(telemetry, policy, registry) for policy in policies]

    for decision in decisions:
        persist_evaluation_result(decision, db)
    db.commit()
    forward_decisions(decisions)
    return decisions


@app.middleware("http")
async def request_observability_middleware(request, call_next):
    request_id = request.headers.get("X-Request-ID", "").strip() or str(uuid4())
    started_at = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started_at) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/evaluate/{endpoint_id}", response_model=ComplianceDecision)
def evaluate_endpoint(
    endpoint_id: str,
    request: Request,
    policy_id: int | None = Query(default=None),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> ComplianceDecision:
    source_ip = request.client.host if request.client else "unknown"
    _apply_evaluation_rate_limit(f"evaluate:{source_ip}")
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            telemetry_future = pool.submit(fetch_latest_telemetry, endpoint_id)
            policies_future = pool.submit(fetch_policies, endpoint_id)
            telemetry = telemetry_future.result()
            policies = policies_future.result()
    except RequestException as exc:
        logger.warning("upstream call failed for endpoint_id=%s error=%s", endpoint_id, exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to fetch telemetry or policy from upstream services",
        ) from exc

    if policy_id is not None:
        policies = [policy for policy in policies if policy.id == policy_id]
        if not policies:
            raise HTTPException(status_code=404, detail="Assigned policy not found for endpoint")

    decisions = evaluate_and_store_decisions(telemetry, policies, db)
    return decisions[0]


@app.post("/evaluate-all/{endpoint_id}", response_model=list[ComplianceDecision])
def evaluate_all_endpoint_policies(
    endpoint_id: str,
    request: Request,
    policy_id: int | None = Query(default=None),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[ComplianceDecision]:
    source_ip = request.client.host if request.client else "unknown"
    _apply_evaluation_rate_limit(f"evaluate-all:{source_ip}")
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            telemetry_future = pool.submit(fetch_latest_telemetry, endpoint_id)
            policies_future = pool.submit(fetch_policies, endpoint_id)
            telemetry = telemetry_future.result()
            policies = policies_future.result()
    except RequestException as exc:
        logger.warning("upstream call failed for endpoint_id=%s error=%s", endpoint_id, exc)
        raise HTTPException(
            status_code=502,
            detail="Failed to fetch telemetry or policies from upstream services",
        ) from exc

    if policy_id is not None:
        policies = [policy for policy in policies if policy.id == policy_id]
        if not policies:
            raise HTTPException(status_code=404, detail="Assigned policy not found for endpoint")

    return evaluate_and_store_decisions(telemetry, policies, db)


@app.get("/results/{endpoint_id}/latest", response_model=ComplianceDecision)
def latest_result(
    endpoint_id: str,
    policy_id: int | None = Query(default=None),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> ComplianceDecision:
    query = select(EvaluationResultModel).where(EvaluationResultModel.endpoint_id == endpoint_id)
    if policy_id is not None:
        query = query.where(EvaluationResultModel.policy_id == policy_id)
    result = db.scalar(query.order_by(desc(EvaluationResultModel.created_at), desc(EvaluationResultModel.id)))
    if result is None:
        raise HTTPException(status_code=404, detail="Evaluation result not found")
    return ComplianceDecision.model_validate(result.raw_result)


@app.get("/results/{endpoint_id}", response_model=list[ComplianceDecision])
def result_history(
    endpoint_id: str,
    policy_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> list[ComplianceDecision]:
    query = select(EvaluationResultModel).where(EvaluationResultModel.endpoint_id == endpoint_id)
    if policy_id is not None:
        query = query.where(EvaluationResultModel.policy_id == policy_id)
    results = db.scalars(query.order_by(desc(EvaluationResultModel.created_at), desc(EvaluationResultModel.id)).limit(limit)).all()
    return [ComplianceDecision.model_validate(item.raw_result) for item in results]


@app.get("/results/latest-batch", response_model=dict[str, ComplianceDecision | None])
def latest_result_batch(
    endpoint_id: list[str] = Query(default=[]),
    policy_id: int | None = Query(default=None),
    _: None = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, ComplianceDecision | None]:
    endpoint_ids = [item.strip() for item in endpoint_id if item.strip()]
    response: dict[str, ComplianceDecision | None] = {item: None for item in endpoint_ids}
    if not endpoint_ids:
        return response

    query = select(EvaluationResultModel).where(EvaluationResultModel.endpoint_id.in_(endpoint_ids))
    if policy_id is not None:
        query = query.where(EvaluationResultModel.policy_id == policy_id)
    rows = db.scalars(
        query.order_by(EvaluationResultModel.endpoint_id, desc(EvaluationResultModel.created_at), desc(EvaluationResultModel.id))
    ).all()
    for row in rows:
        if response.get(row.endpoint_id) is None:
            response[row.endpoint_id] = ComplianceDecision.model_validate(row.raw_result)
    return response


@app.post("/evaluate-inline", response_model=ComplianceDecision)
def evaluate_inline(
    payload: InlineEvaluationRequest,
    _: None = Depends(require_api_key),
) -> ComplianceDecision:
    return evaluate_telemetry(payload.telemetry, payload.policy, registry)
