import logging
from datetime import datetime
from typing import Dict, Any, List

# We'll use a simple HTML to PDF approach or just generate HTML for now if reportlab isn't guaranteed
# But let's try to structure it so it can be extended.
# For this implementation, we'll generate a Markdown report that can be converted, 
# as adding a heavy PDF dependency might complicate the environment without user input.
# However, the requirement was "PDF report generation".
# I'll implement a class that *would* use reportlab, but with a fallback or a placeholder 
# if the library is missing, to avoid crashing.

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        pass

    def generate_scan_report(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]], output_path: str) -> bool:
        """
        Generate a PDF report for a scan.
        """
        try:
            # Check for reportlab
            try:
                from reportlab.lib import colors
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.styles import getSampleStyleSheet
            except ImportError:
                logger.warning("ReportLab not installed. Generating Markdown report instead.")
                return self._generate_markdown_report(scan_data, findings, output_path.replace('.pdf', '.md'))

            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            # Title
            story.append(Paragraph(f"Security Scan Report: {scan_data.get('repo_name')}", styles['Title']))
            story.append(Spacer(1, 12))
            
            # Metadata
            story.append(Paragraph(f"Scan ID: {scan_data.get('scan_id')}", styles['Normal']))
            story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
            story.append(Spacer(1, 24))

            # Summary Table
            story.append(Paragraph("Summary", styles['Heading2']))
            data = [
                ["Metric", "Value"],
                ["Total Findings", str(len(findings))],
                ["Critical", str(sum(1 for f in findings if f.get('severity') == 'critical'))],
                ["High", str(sum(1 for f in findings if f.get('severity') == 'high'))],
            ]
            t = Table(data)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(t)
            story.append(Spacer(1, 24))

            # Findings
            story.append(Paragraph("Detailed Findings", styles['Heading2']))
            for finding in findings:
                story.append(Paragraph(f"{finding.get('title')} ({finding.get('severity')})", styles['Heading3']))
                story.append(Paragraph(f"File: {finding.get('file_path')}", styles['Normal']))
                story.append(Paragraph(f"Description: {finding.get('description')}", styles['Normal']))
                story.append(Spacer(1, 12))

            doc.build(story)
            logger.info(f"PDF report generated at {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return False

    def _generate_markdown_report(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]], output_path: str) -> bool:
        """Fallback Markdown generator."""
        try:
            with open(output_path, 'w') as f:
                f.write(f"# Security Scan Report: {scan_data.get('repo_name')}\n\n")
                f.write(f"**Scan ID:** {scan_data.get('scan_id')}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
                
                f.write("## Summary\n\n")
                f.write(f"- Total Findings: {len(findings)}\n")
                f.write(f"- Critical: {sum(1 for f in findings if f.get('severity') == 'critical')}\n")
                f.write(f"- High: {sum(1 for f in findings if f.get('severity') == 'high')}\n\n")
                
                f.write("## Detailed Findings\n\n")
                for finding in findings:
                    f.write(f"### {finding.get('title')} ({finding.get('severity')})\n")
                    f.write(f"- **File:** `{finding.get('file_path')}`\n")
                    f.write(f"- **Description:** {finding.get('description')}\n\n")
            
            logger.info(f"Markdown report generated at {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            return False
