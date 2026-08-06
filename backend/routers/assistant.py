"""
AI assistant router.
POST /ask-ai — answer user questions about an investigation.
"""
import logging

from fastapi import APIRouter, HTTPException, status

from schemas import AskAIRequest, AskAIResponse
from services.ai import answer_question

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assistant"])


@router.post("/ask-ai", response_model=AskAIResponse)
async def ask_ai(req: AskAIRequest):
    if not req.question.strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Question cannot be empty")

    try:
        answer = await answer_question(req.question, req.investigation)
        return AskAIResponse(answer=answer)
    except Exception as exc:
        logger.exception("AI assistant error: %s", exc)
        raise HTTPException(status_code=500, detail=f"AI assistant error: {exc}")
