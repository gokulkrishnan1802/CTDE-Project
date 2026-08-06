export function generateCaseId(existing: number): string {
  const year = new Date().getFullYear();
  return `CTDE-${year}-${String(existing + 1).padStart(4, '0')}`;
}

export { generatePDFReport } from '../services/reportService';
