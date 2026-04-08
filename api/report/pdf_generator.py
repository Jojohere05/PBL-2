"""
PDF Report Generator
"""
from typing import List, Dict, Any
from datetime import datetime
import io


class PDFReportGenerator:
    """Generates PDF reports for scan results"""
    
    def __init__(self):
        self.company_name = "FinGuard Security"
    
    def generate_report(
        self,
        scan_id: str,
        repo_name: str,
        findings: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> bytes:
        """Generate PDF report"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a365d')
            )
            elements.append(Paragraph("Security Scan Report", title_style))
            elements.append(Spacer(1, 0.25 * inch))
            
            # Metadata
            elements.append(Paragraph(f"<b>Repository:</b> {repo_name}", styles['Normal']))
            elements.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", styles['Normal']))
            elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            elements.append(Spacer(1, 0.5 * inch))
            
            # Summary
            elements.append(Paragraph("Executive Summary", styles['Heading2']))
            
            summary_data = [
                ['Severity', 'Count'],
                ['Critical', str(summary.get('by_severity', {}).get('critical', 0))],
                ['High', str(summary.get('by_severity', {}).get('high', 0))],
                ['Medium', str(summary.get('by_severity', {}).get('medium', 0))],
                ['Low', str(summary.get('by_severity', {}).get('low', 0))],
                ['Total', str(summary.get('total_findings', 0))]
            ]
            
            summary_table = Table(summary_data, colWidths=[2 * inch, 1.5 * inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.5 * inch))
            
            # Risk Score
            risk_score = summary.get('risk_score', 0)
            elements.append(Paragraph(f"<b>Risk Score:</b> {risk_score}/100", styles['Normal']))
            elements.append(Spacer(1, 0.5 * inch))
            
            # Findings
            elements.append(Paragraph("Detailed Findings", styles['Heading2']))
            
            # Group findings by severity
            for severity in ['critical', 'high', 'medium', 'low']:
                severity_findings = [f for f in findings if f.get('severity') == severity]
                if severity_findings:
                    elements.append(Paragraph(f"{severity.upper()} ({len(severity_findings)})", styles['Heading3']))
                    
                    for finding in severity_findings[:20]:  # Limit to 20 per severity
                        elements.append(Paragraph(f"<b>{finding.get('rule_id')}</b>", styles['Normal']))
                        elements.append(Paragraph(f"Description: {finding.get('description')}", styles['Normal']))
                        elements.append(Paragraph(f"File: {finding.get('file_path')} (line {finding.get('line', 'N/A')})", styles['Normal']))
                        elements.append(Spacer(1, 0.2 * inch))
            
            # Build PDF
            doc.build(elements)
            buffer.seek(0)
            return buffer.getvalue()
            
        except ImportError:
            # Fallback to simple text if reportlab not available
            return self._generate_text_report(scan_id, repo_name, findings, summary)
    
    def _generate_text_report(
        self,
        scan_id: str,
        repo_name: str,
        findings: List[Dict],
        summary: Dict
    ) -> bytes:
        """Generate simple text report as fallback"""
        report = f"""
SECURITY SCAN REPORT
{'=' * 50}

Repository: {repo_name}
Scan ID: {scan_id}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
{'=' * 50}
Critical: {summary.get('by_severity', {}).get('critical', 0)}
High: {summary.get('by_severity', {}).get('high', 0)}
Medium: {summary.get('by_severity', {}).get('medium', 0)}
Low: {summary.get('by_severity', {}).get('low', 0)}
Total: {summary.get('total_findings', 0)}

Risk Score: {summary.get('risk_score', 0)}/100

FINDINGS
{'=' * 50}
"""
        for finding in findings:
            report += f"""
[{finding.get('severity', 'UNKNOWN').upper()}] {finding.get('rule_id')}
  Description: {finding.get('description')}
  File: {finding.get('file_path')} (line {finding.get('line', 'N/A')})
"""
        
        return report.encode('utf-8')


def create_generator() -> PDFReportGenerator:
    """Factory function to create PDF generator"""
    return PDFReportGenerator()


def generate_pdf_report(result: Dict[str, Any], output_path: str) -> str:
    """Generate and save a PDF report from scan result payload."""
    generator = create_generator()

    summary = result.get("summary", {})
    by_severity = summary.get("by_severity", {})

    normalized_summary = {
        "by_severity": {
            "critical": by_severity.get("CRITICAL", by_severity.get("critical", 0)),
            "high": by_severity.get("HIGH", by_severity.get("high", 0)),
            "medium": by_severity.get("MEDIUM", by_severity.get("medium", 0)),
            "low": by_severity.get("LOW", by_severity.get("low", 0)),
        },
        "total_findings": summary.get("total", summary.get("total_findings", 0)),
        "risk_score": result.get("risk_score", summary.get("risk_score", 0)),
    }

    report_bytes = generator.generate_report(
        scan_id=result.get("scan_id", "manual-scan"),
        repo_name=result.get("repo", "uploaded-repository"),
        findings=result.get("violations", []),
        summary=normalized_summary,
    )

    with open(output_path, "wb") as f:
        f.write(report_bytes)

    return output_path
