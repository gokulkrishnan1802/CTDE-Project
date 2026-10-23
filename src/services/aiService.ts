import type { ChatMessage, Investigation } from '../types';
import { postAskAI } from './api';

export async function askAI(
  question: string,
  investigation?: Investigation | null,
  history: ChatMessage[] = [],
): Promise<string> {
  const context = investigation
    ? {
        ...investigation.analysis,
        evidenceType: investigation.evidenceType,
        evidenceValue: investigation.evidenceValue,
        caseId: investigation.caseId,
      }
    : null;

  const response = await postAskAI({
    question: question.trim(),
    investigation: context,
    history: history.slice(-10).map(({ role, content }) => ({ role, content })),
  });

  return response.answer;
}