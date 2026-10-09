import type { Investigation } from '../types';
import { jsPDF } from 'jspdf';

const LEFT = 15;
const RIGHT = 15;
// Slightly tighter vertical rhythm keeps common reports on fewer pages.
const LINE_HEIGHT = 4.2;
const HEADER_HEIGHT = 35;
const CONTENT_TOP = 47;
const FOOTER_LINE_Y = 280;
const BOTTOM_LIMIT = 272;

function pdfText(value: unknown): string {
  return String(value ?? '')
    .replace(/\u0000/g, '')
    .replace(/\r\n?/g, '\n')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '?');
}

function display(value: unknown): string {
  const safe = pdfText(value).trim();
  return safe || 'Not available';
}

function localDate(value: unknown): string {
  const date = new Date(String(value ?? ''));
  return Number.isNaN(date.getTime()) ? display(value) : date.toLocaleString();
}

export function generatePDFReport(inv: Investigation): void {
  const doc = new jsPDF({ compress: true });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const contentWidth = pageWidth - LEFT - RIGHT;
  const generatedAt = new Date().toLocaleString();
  let y = CONTENT_TOP;

  const drawHeader = () => {
    doc.setFillColor(10, 14, 20);
    doc.rect(0, 0, pageWidth, HEADER_HEIGHT, 'F');
    doc.setTextColor(0, 220, 240);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('CyberTrust Decision Engine (CTDE)', LEFT, 15);
    doc.setTextColor(210, 220, 230);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.text('Digital Forensics Investigation Report', LEFT, 25);
    doc.text(`Generated: ${pdfText(generatedAt)}`, pageWidth - RIGHT, 25, {
      align: 'right',
    });
  };

  const startPage = (continuedSection?: string) => {
    doc.addPage();
    drawHeader();
    y = CONTENT_TOP;
    if (continuedSection) drawSectionHeading(`${continuedSection} (continued)`);
  };

  const drawSectionHeading = (title: string) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(0, 100, 150);
    doc.text(pdfText(title), LEFT, y);
    y += 5.5;
  };

  const addSection = (title: string, content: unknown) => {
    const safeTitle = pdfText(title);
    const safeContent = display(content);
    const lines = (doc.splitTextToSize(safeContent, contentWidth) as string[]) || [];
    const wrappedLines = lines.length ? lines : ['Not available'];

    // Keep each heading with at least two lines of its content.
    if (y + 5.5 + Math.min(wrappedLines.length, 2) * LINE_HEIGHT > BOTTOM_LIMIT) {
      startPage();
    }

    // Avoid leaving a short section (such as the timeline) split over two pages.
    const fitsOnFreshPage =
      5.5 + wrappedLines.length * LINE_HEIGHT <= BOTTOM_LIMIT - CONTENT_TOP;
    if (
      fitsOnFreshPage &&
      y + 5.5 + wrappedLines.length * LINE_HEIGHT > BOTTOM_LIMIT
    ) {
      startPage();
    }
    drawSectionHeading(safeTitle);

    let offset = 0;
    while (offset < wrappedLines.length) {
      const linesAvailable = Math.floor((BOTTOM_LIMIT - y) / LINE_HEIGHT);
      if (linesAvailable < 1) {
        startPage(safeTitle);
        continue;
      }

      const pageLines = wrappedLines.slice(offset, offset + linesAvailable);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(55, 65, 81);
      doc.text(pageLines, LEFT, y);
      y += pageLines.length * LINE_HEIGHT;
      offset += pageLines.length;

      if (offset < wrappedLines.length) startPage(safeTitle);
    }
    y += 2;
  };

  drawHeader();

  const panel = inv.evidencePanel;
  addSection(
    'Case Details',
    [
      `Case ID: ${display(inv.caseId)}`,
      `Case name: ${display(inv.caseName)}`,
      `Evidence type: ${display(inv.evidenceType).toUpperCase()}`,
      `Investigator: ${display(inv.investigator)}`,
      `Created: ${localDate(inv.createdAt)}`,
      `Heuristic score: ${display(inv.trustScore)}/100`,
      `Risk label: ${display(inv.riskLevel)}`,
      'Score calibration: Not benchmarked',
      'Evidence value:',
      display(inv.evidenceValue),
    ].join('\n'),
  );

  addSection(
    'Evidence Information',
    [
      `SHA-256: ${display(panel?.sha256Hash)}`,
      `Original URL: ${display(panel?.originalUrl)}`,
      `Resolved URL: ${display(panel?.resolvedUrl)}`,
      `IP address: ${display(panel?.ipAddress)}`,
      `Hosting provider: ${display(panel?.hostingProvider)}`,
      `Country: ${display(panel?.country)}`,
      `Registrar: ${display(panel?.registrar)}`,
      `SSL status: ${display(panel?.sslStatus)}`,
      `WHOIS status: ${display(panel?.whoisStatus)}`,
    ].join('\n'),
  );

  addSection('Evidence Summary', inv.analysis.evidenceSummary);

  const processed = inv.analysis.evidenceProcessing;
  if (processed) {
    const indicatorLines = Object.entries(processed.indicators || {}).map(
      ([kind, values]) =>
        `${kind}: ${Array.isArray(values) && values.length ? values.map(display).join(', ') : 'None'}`,
    );
    const relationshipLines = (processed.relationships || []).map(
      (item) =>
        `${display(item.source)} -> ${pdfText(item.relationship || 'related').replace(/_/g, ' ')} -> ${display(item.target)}`,
    );
    const correlation = processed.crossInvestigationCorrelation;
    const correlationLines = correlation
      ? [
          `Cross-investigation status: ${display(correlation.status)}`,
          `Prior investigations searched: ${display(correlation.searchedInvestigations)}`,
          `Prior investigation matches: ${display(correlation.matchCount)}`,
          ...(correlation.matches || []).map((match) =>
            `${display(match.caseId)} (${display(match.evidenceType)}, ${display(match.riskLevel)}) shared: ${(match.matchingIndicators || [])
              .map((item) => `${display(item.type)}: ${display(item.value)}`)
              .join(', ') || 'None'}`,
          ),
        ]
      : [];

    addSection(
      'Evidence Processing & Correlation',
      [
        processed.processed
          ? 'Processing completed.'
          : `Processing failed: ${display(processed.error)}`,
        `Indicators: ${processed.summary?.totalIndicators ?? 0}`,
        `Relationships: ${processed.summary?.totalRelationships ?? 0}`,
        ...indicatorLines,
        ...relationshipLines,
        ...correlationLines,
      ].join('\n'),
    );
  }

  addSection('Identity Verification', inv.analysis.identityVerification);
  addSection('Domain Verification', inv.analysis.domainVerification);
  addSection('Certificate Validation', inv.analysis.certificateValidation);
  addSection('WHOIS Information', inv.analysis.whoisInfo);
  addSection('Brand Impersonation Analysis', inv.analysis.brandImpersonation);
  addSection('URL Analysis', inv.analysis.urlAnalysis);

  if (inv.analysis.apkPermissionAnalysis) {
    addSection('APK Permission Analysis', inv.analysis.apkPermissionAnalysis);
  }
  if (inv.analysis.senderVerification) {
    addSection('Sender Verification', inv.analysis.senderVerification);
  }
  if (inv.analysis.qrVerification) {
    addSection('QR Destination Verification', inv.analysis.qrVerification);
  }

  addSection('Reputation Analysis', inv.analysis.reputationAnalysis);
  addSection(
    'MITRE ATT&CK Mapping',
    (inv.analysis.mitreMapping || []).join('\n') || 'No techniques mapped.',
  );
  addSection('Analysis Explanation', inv.analysis.aiExplanation);
  addSection('Analysis Summary', inv.analysis.aiSummary);
  addSection(
    'Recommendations',
    (inv.analysis.recommendations || []).length
      ? inv.analysis.recommendations.map((item, index) => `${index + 1}. ${item}`).join('\n')
      : 'No recommendations were generated.',
  );

  if (inv.timeline?.length) {
    addSection(
      'Investigation Timeline',
      inv.timeline
        .map(
          (event) =>
            `${new Date(event.timestamp).toLocaleTimeString()} - ${display(event.label)}`,
        )
        .join('\n'),
    );
  }

  const pageCount = doc.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(200, 200, 200);
    doc.line(LEFT, FOOTER_LINE_Y, pageWidth - RIGHT, FOOTER_LINE_Y);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text('Department of Cyber Security - College Project', LEFT, pageHeight - 10);
    doc.text(`Page ${page} of ${pageCount}`, pageWidth - RIGHT, pageHeight - 10, {
      align: 'right',
    });
  }

  doc.save(`CTDE_Report_${pdfText(inv.caseId)}.pdf`);
}
