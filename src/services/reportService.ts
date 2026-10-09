import type { Investigation } from '../types';
import { jsPDF } from 'jspdf';

const LEFT = 14;
const RIGHT = 14;
const LINE_HEIGHT = 4.5;

function pdfText(value: unknown): string {
  return String(value ?? '')
    .replace(/\u0000/g, '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '?');
}

export function generatePDFReport(inv: Investigation): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const contentWidth = pageWidth - LEFT - RIGHT;
  const bottomLimit = pageHeight - 24;
  let y = 50;

  doc.setFillColor(10, 14, 20);
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor(0, 220, 240);
  doc.setFontSize(17);
  doc.setFont('helvetica', 'bold');
  doc.text('CyberTrust Decision Engine (CTDE)', LEFT, 18);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(210, 220, 230);
  doc.text('Digital Forensics Investigation Report', LEFT, 27);
  doc.setFontSize(8);
  doc.text(
    `Generated: ${pdfText(new Date().toLocaleString())}`,
    pageWidth - RIGHT,
    27,
    { align: 'right' },
  );

  const startPage = () => {
    doc.addPage();
    y = 20;
  };

  const addSection = (title: string, content: unknown) => {
    const safeTitle = pdfText(title);
    const safeContent = pdfText(content) || 'Not available';
    const lines = doc.splitTextToSize(safeContent, contentWidth) as string[];

    // Keep each heading with at least its first line of content.
    if (y + 7 + LINE_HEIGHT > bottomLimit) startPage();

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(0, 100, 150);
    doc.text(safeTitle, LEFT, y);
    y += 7;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(55, 65, 81);

    let offset = 0;
    while (offset < lines.length) {
      const linesAvailable = Math.floor((bottomLimit - y) / LINE_HEIGHT);
      if (linesAvailable < 1) {
        startPage();
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(55, 65, 81);
        continue;
      }

      const pageLines = lines.slice(offset, offset + linesAvailable);
      doc.text(pageLines, LEFT, y);
      y += pageLines.length * LINE_HEIGHT;
      offset += pageLines.length;

      if (offset < lines.length) startPage();
    }
    y += 4;
  };

  addSection(
    'Case Details',
    [
      `Case ID: ${inv.caseId}`,
      `Case name: ${inv.caseName}`,
      `Evidence type: ${inv.evidenceType.toUpperCase()}`,
      `Evidence value: ${inv.evidenceValue}`,
      `Investigator: ${inv.investigator}`,
      `Created: ${new Date(inv.createdAt).toLocaleString()}`,
      `Heuristic score: ${inv.trustScore}/100`,
      `Risk label: ${inv.riskLevel}`,
      'Score calibration: Not benchmarked',
    ].join('\n'),
  );

  addSection(
    'Evidence Information',
    [
      `SHA-256: ${inv.evidencePanel.sha256Hash}`,
      `Resolved URL: ${inv.evidencePanel.resolvedUrl}`,
      `IP address: ${inv.evidencePanel.ipAddress}`,
      `Hosting provider: ${inv.evidencePanel.hostingProvider}`,
      `Country: ${inv.evidencePanel.country}`,
      `Registrar: ${inv.evidencePanel.registrar}`,
      `SSL status: ${inv.evidencePanel.sslStatus}`,
      `WHOIS status: ${inv.evidencePanel.whoisStatus}`,
    ].join('\n'),
  );

  addSection('Evidence Summary', inv.analysis.evidenceSummary);

  const processed = inv.analysis.evidenceProcessing;
  if (processed) {
    const indicatorLines = Object.entries(processed.indicators || {}).map(
      ([kind, values]) =>
        `${kind}: ${Array.isArray(values) && values.length ? values.join(', ') : 'None'}`,
    );
    const relationshipLines = (processed.relationships || []).map(
      (item) => `${item.source} -> ${item.relationship.replace(/_/g, ' ')} -> ${item.target}`,
    );
    const correlation = processed.crossInvestigationCorrelation;
    const correlationLines = correlation
      ? [
          `Cross-investigation status: ${correlation.status}`,
          `Prior investigations searched: ${correlation.searchedInvestigations}`,
          `Prior investigation matches: ${correlation.matchCount}`,
          ...correlation.matches.map((match) =>
            `${match.caseId} (${match.evidenceType}, ${match.riskLevel}) shared: ${match.matchingIndicators
              .map((item) => `${item.type}: ${item.value}`)
              .join(', ')}`,
          ),
        ]
      : [];

    addSection(
      'Evidence Processing and Correlation',
      [
        processed.processed
          ? 'Processing completed.'
          : `Processing failed: ${processed.error || 'Unknown error'}`,
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
  addSection('MITRE ATT&CK Mapping', inv.analysis.mitreMapping.join('\n'));
  addSection('Analysis Explanation', inv.analysis.aiExplanation);
  addSection('Analysis Summary', inv.analysis.aiSummary);
  addSection('Recommendations', inv.analysis.recommendations.join('\n'));

  if (inv.timeline?.length) {
    addSection(
      'Investigation Timeline',
      inv.timeline
        .map(
          (event) =>
            `${new Date(event.timestamp).toLocaleTimeString()} - ${event.label}`,
        )
        .join('\n'),
    );
  }

  const pageCount = doc.getNumberOfPages();
  for (let page = 1; page <= pageCount; page += 1) {
    doc.setPage(page);
    doc.setDrawColor(200, 200, 200);
    doc.line(LEFT, pageHeight - 18, pageWidth - RIGHT, pageHeight - 18);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text(
      'Department of Cyber Security - College Project',
      LEFT,
      pageHeight - 12,
    );
    doc.text(`Page ${page} of ${pageCount}`, pageWidth - RIGHT, pageHeight - 12, {
      align: 'right',
    });
  }

  doc.save(`CTDE_Report_${pdfText(inv.caseId)}.pdf`);
}