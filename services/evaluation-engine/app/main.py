from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from requests import RequestException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.client import fetch_latest_telemetry, fetch_policy, forward_decision
from app.db import Base, engine, get_db
from app.evaluators import build_registry
from app.models import EvaluationResultModel
from app.service import evaluate_telemetry
from posture_shared.models.evaluation import ComplianceDecision
from posture_shared.models.policy import PosturePolicy
from posture_shared.models.telemetry import EndpointTelemetry


Base.metadata.create_all(bind=engine)
app = FastAPI(title="evaluation-engine", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
registry = build_registry()


class InlineEvaluationRequest(BaseModel):
    telemetry: EndpointTelemetry
    policy: PosturePolicy | None = None


@app.get("/healthz")
def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/evaluate/{endpoint_id}", response_model=ComplianceDecision)
def evaluate_endpoint(endpoint_id: str, db: Session = Depends(get_db)) -> ComplianceDecision:
    try:
        telemetry = fetch_latest_telemetry(endpoint_id)
        policy = fetch_policy(endpoint_id)
    except RequestException as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    decision = evaluate_telemetry(telemetry, policy, registry)
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
    db.commit()

    try:
        forward_decision(decision)
    except RequestException:
        pass

    return decision


@app.get("/results/{endpoint_id}/latest", response_model=ComplianceDecision)
def latest_result(endpoint_id: str, db: Session = Depends(get_db)) -> ComplianceDecision:
    result = db.scalar(
        select(EvaluationResultModel)
        .where(EvaluationResultModel.endpoint_id == endpoint_id)
        .order_by(desc(EvaluationResultModel.created_at))
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Evaluation result not found")
    return ComplianceDecision.model_validate(result.raw_result)


@app.get("/results/{endpoint_id}", response_model=list[ComplianceDecision])
def result_history(endpoint_id: str, db: Session = Depends(get_db)) -> list[ComplianceDecision]:
    results = db.scalars(
        select(EvaluationResultModel)
        .where(EvaluationResultModel.endpoint_id == endpoint_id)
        .order_by(desc(EvaluationResultModel.created_at))
    ).all()
    return [ComplianceDecision.model_validate(item.raw_result) for item in results]


@app.post("/evaluate-inline", response_model=ComplianceDecision)
def evaluate_inline(payload: InlineEvaluationRequest) -> ComplianceDecision:
    return evaluate_telemetry(payload.telemetry, payload.policy, registry)
