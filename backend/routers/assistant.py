"""
AI assistant router.
POST /ask-ai — answer user questions about an investigation.
"""
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from auth import get_current_user
from models import User
from schemas import AskAIRequest, AskAIResponse
from services.ai import answer_question

logger = logging.getLogger(__name__)
router = APIRouter(tags=["assistant"])


@router.post("/ask-ai", response_model=AskAIResponse)
async def ask_ai(
    req: AskAIRequest,
    _current_user: User = Depends(get_current_user),
):
    if not req.question.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Question cannot be empty",
        )

    context_size = len(json.dumps(req.investigation, default=str))
    if context_size > 20_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Investigation context is too large for the AI assistant.",
        )

    try:
        answer = await answer_question(req.question, req.investigation)
        return AskAIResponse(answer=answer)
    except Exception as exc:
        logger.exception("AI assistant error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AI assistant could not answer right now.",
        ) from exc