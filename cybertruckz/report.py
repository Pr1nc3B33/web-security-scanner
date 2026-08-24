from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

def format_report(url, findings):
    lines = []
    lines.append(f"Security scan report for: {url}")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("=" * 50)

    for severity in ["High", "Medium", "Low"]:
        matched = [f for f in findings if f["severity"] == severity]

        if matched:
            lines.append(f"\n{severity.upper()} ({len(matched)})")
            lines.append("-" * 20)

            for item in matched:
                lines.append(f"Title: {item.get('title', 'N/A')}")
                lines.append(f"Detail: {item.get('detail')}")
                lines.append(f"Recommendation: {item.get('recommendation')}")
                lines.append("")



    return "\n".join(lines)

def generate_pdf_report(url, findings, filename="security_report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=letter) 
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#0A1F3D"),
    )
    heading_style = ParagraphStyle(
        "SeverityHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#00C8E6"),
    )

    story = []
    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",styles["Normal"]))
    story.append(Paragraph(f"Target: {url}", styles["Normal"]))
    story.append(Paragraph(f"Total findings: {len(findings)}", styles["Normal"]))
    story.append(Spacer(1, 20))

    for severity in ["High", "Medium", "Low"]:
        matched = [f for f in findings if f["severity"] == severity]

        if matched:
            story.append(Paragraph(f"{severity.upper()} ({len(matched)})", heading_style))
            story.append(Spacer(1, 6))

            for item in matched:
                title = item.get("title", "N/A")
                detail = item.get("detail", "No details provided.")
                rec = item.get("recommendation", "No recommendation provided.")
                
                story.append(Paragraph(f"<b>Title:</b> {title}", styles["Normal"]))
                story.append(Paragraph(f"<b>Detail:</b> {detail}", styles["Normal"]))
                story.append(Paragraph(f"<b>Recommendation:</b> {rec}", styles["Normal"]))

                story.append(Spacer(1, 12))
                



    doc.build(story)
    return filename    