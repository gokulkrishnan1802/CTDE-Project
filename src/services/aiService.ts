import type { Investigation } from '../types';
import { postAskAI } from './api';

export async function askAI(
  question: string,
  investigation: Investigation,
): Promise<string> {
  const normalizedQuestion = question
    .trim()
    .toLowerCase()
    .replace(/[!?.,]+$/g, '');

  if (
    /^(hi|hello|hey|good morning|good afternoon|good evening)( there)?$/.test(
      normalizedQuestion,
    )
  ) {
    return `Hi! I can explain the findings for case ${investigation.caseId}. Ask me about the score, email authentication, reputation checks, or recommendations.`;
  }

  const context = {
    ...investigation.analysis,
    evidenceType: investigation.evidenceType,
    evidenceValue: investigation.evidenceValue,
    caseId: investigation.caseId,
  };

  const response = await postAskAI({
    question: question.trim(),
    investigation: context,
  });

  return response.answer;
}