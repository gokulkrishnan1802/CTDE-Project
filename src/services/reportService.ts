import type { Investigation } from '../types';
import { jsPDF } from 'jspdf';

export function generatePDFReport(inv: Investigation): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 0;

  doc.setFillColor(10, 14, 20);
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor(0, 240, 255);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text('CyberTrust Decision Engine (CTDE)', 14, 18);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(180, 180, 180);
  doc.text('Digital Forensics Investigation Platform — Powered by AI', 14, 26);
  doc.setFontSize(8);
  doc.text(`Report Generated: ${new Date().toLocaleString()}`, pageWidth - 14, 26, { align: 'right' });

  y = 50;

  doc.setDrawColor(200, 200, 200);
  doc.setFillColor(245, 245, 245);
  doc.roundedRect(14, y, pageWidth - 28, 30, 2, 2, 'FD');
  doc.setTextColor(40, 40, 40);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(`Case ID: ${inv.caseId}`, 18, y + 10);
  doc.text(`Risk Level: ${inv.riskLevel}`, pageWidth - 18, y + 10, { align: 'right' });
  doc.setFont('helvetica', 'normal');
  doc.text(`Case Name: ${inv.caseName}`, 18, y + 18);
  doc.text(`Trust Score: ${inv.trustScore}/100`, pageWidth - 18, y + 18, { align: 'right' });
  doc.text(`Investigator: ${inv.investigator}`, 18, y + 26);
  doc.text(`Date: ${new Date(inv.createdAt).toLocaleString()}`, pageWidth - 18, y + 26, { align: 'right' });

  y += 40;

  const addSection = (title: string, content: string) => {
    if (y > 270) { doc.addPage(); y = 20; }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(0, 100, 150);
    doc.text(title, 14, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    const lines = doc.splitTextToSize(content, pageWidth - 28);
    if (y + lines.length * 5 > 280) { doc.addPage(); y = 20; }
    doc.text(lines, 14, y);
    y += lines.length * 5 + 4;
  };

  addSection('Evidence Information', `Type: ${inv.evidenceType.toUpperCase()}\nValue: ${inv.evidenceValue}\nSHA256 Hash: ${inv.evidencePanel.sha256Hash}\nResolved URL: ${inv.evidencePanel.resolvedUrl}\nIP Address: ${inv.evidencePanel.ipAddress}\nHosting Provider: ${inv.evidencePanel.hostingProvider}\nCountry: ${inv.evidencePanel.country}\nRegistrar: ${inv.evidencePanel.registrar}\nSSL Status: ${inv.evidencePanel.sslStatus}\nWHOIS Status: ${inv.evidencePanel.whoisStatus}`);

  addSection('Evidence Summary', inv.analysis.evidenceSummary);
  addSection('Identity Verification', inv.analysis.identityVerification);
  addSection('Domain Verification', inv.analysis.domainVerification);
  addSection('Certificate Details', inv.analysis.certificateValidation);
  addSection('WHOIS Information', inv.analysis.whoisInfo);
  addSection('Brand Impersonation Detection', inv.analysis.brandImpersonation);
  addSection('URL Analysis', inv.analysis.urlAnalysis);
  if (inv.analysis.apkPermissionAnalysis) addSection('APK Permission Analysis', inv.analysis.apkPermissionAnalysis);
  if (inv.analysis.senderVerification) addSection('Sender Verification', inv.analysis.senderVerification);
  if (inv.analysis.qrVerification) addSection('QR Destination Verification', inv.analysis.qrVerification);
  addSection('Reputation Analysis', inv.analysis.reputationAnalysis);

  if (y > 250) { doc.addPage(); y = 20; }
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 100, 150);
  doc.text('MITRE ATT&CK Mapping', 14, y);
  y += 6;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(60, 60, 60);
  inv.analysis.mitreMapping.forEach(m => {
    if (y > 280) { doc.addPage(); y = 20; }
    doc.text(`  - ${m}`, 14, y);
    y += 5;
  });
  y += 4;

  addSection('Digital Trust Score', `Score: ${inv.trustScore}/100\nRisk Level: ${inv.riskLevel}\nAI Confidence: ${inv.aiConfidence}%`);
  addSection('AI Explanation', inv.analysis.aiExplanation);
  addSection('AI Summary', inv.analysis.aiSummary);

  if (y > 250) { doc.addPage(); y = 20; }
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(0, 100, 150);
  doc.text('Recommendations', 14, y);
  y += 6;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(60, 60, 60);
  inv.analysis.recommendations.forEach((r, i) => {
    if (y > 280) { doc.addPage(); y = 20; }
    doc.text(`${i + 1}. ${r}`, 14, y);
    y += 5;
  });

  if (inv.timeline && inv.timeline.length > 0) {
    if (y > 250) { doc.addPage(); y = 20; }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(0, 100, 150);
    doc.text('Investigation Timeline', 14, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    inv.timeline.forEach((event) => {
      if (y > 280) { doc.addPage(); y = 20; }
      doc.text(`  ${new Date(event.timestamp).toLocaleTimeString()}  —  ${event.label}`, 14, y);
      y += 5;
    });
  }

  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageHeight = doc.internal.pageSize.getHeight();
    doc.setDrawColor(200, 200, 200);
    doc.line(14, pageHeight - 18, pageWidth - 14, pageHeight - 18);
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text('Department of Cyber Security — College Project', 14, pageHeight - 12);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 14, pageHeight - 12, { align: 'right' });
  }

  doc.save(`CTDE_Report_${inv.caseId}.pdf`);
}
