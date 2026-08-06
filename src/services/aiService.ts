import type { Investigation } from '../types';
import { answerQuestion } from '../lib/engine/aiExplainer';

export async function askAI(
  question: string,
  investigation: Investigation,
): Promise<string> {
  const context = {
    ...investigation.analysis,
    evidenceType: investigation.evidenceType,
    evidenceValue: investigation.evidenceValue,
    caseId: investigation.caseId,
  };
  return answerQuestion(question, context as Record<string, unknown>);
}
