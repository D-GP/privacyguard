from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

def make_report(scan, entities, risk):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story = [Paragraph("PrivacyGuard AI — Privacy Assessment", styles["Title"]), Spacer(1, 12),
             Paragraph(f"Scan: {scan.title}", styles["Heading2"]),
             Paragraph(f"Risk: {risk['level']} ({round(risk['score']*100)}%)", styles["BodyText"]),
             Paragraph(f"Entities detected: {len(entities)}", styles["BodyText"]), Spacer(1, 14)]
    rows = [["Entity", "Value", "Confidence", "Source"]]
    rows += [[e.entity_type, e.text[:45], f"{round(e.confidence*100)}%", e.source] for e in entities]
    table = Table(rows, colWidths=[105, 220, 75, 100])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17263b')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),0.25,colors.grey),('FONTSIZE',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'TOP')]))
    story.append(table); story.append(Spacer(1, 16)); story.append(Paragraph("Risk explanation", styles["Heading2"]))
    for item in risk["explanations"]:
        story.append(Paragraph("• " + item, styles["BodyText"]))
    story.append(Spacer(1, 12)); story.append(Paragraph("PrivacyGuard AI is an automated decision-support system. Detection may be incomplete and should be reviewed before sensitive data is shared.", styles["Italic"]))
    doc.build(story); buf.seek(0); return buf
