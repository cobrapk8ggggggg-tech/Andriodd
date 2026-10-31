"""Portable evidence exports; findings retain their classification and limits."""
import html
import io
import json


def render_html(report):
    def escape(value):return html.escape(str(value))
    sections=[]
    for title,key in [('Application','artifact'),('Manifest and components','inventory'),('Findings — not confirmed exploits','findings'),
                      ('Source evidence and coverage','source_observations'),('Runtime correlations','runtime_correlations'),
                      ('Timeline','timeline'),('Recording references','recordings'),('Coverage and limitations','coverage')]:
        sections.append('<section><h2>'+title+'</h2><pre>'+escape(json.dumps(report.get(key,{}),ensure_ascii=False,indent=2))+'</pre></section>')
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        '<title>ZEUS Security Report</title><style>body{font:15px system-ui;background:#0a0d12;color:#e8edf4;max-width:1000px;margin:40px auto;padding:20px}h1{color:#a7edce}section{padding:20px;border:1px solid #303744;border-radius:16px;margin:20px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}h2{font-size:18px}@media print{body{background:white;color:black}section{break-inside:avoid}}</style>'
        '<h1>ZEUS · Security analysis</h1><p>Evidence and unresolved observations are distinct. Absence of captured traffic is not proof of absence.</p>'+''.join(sections)+'</html>').encode()


def render_pdf(report):
    # The portable PDF uses an English cover and UTF-8 JSON/HTML remain the full
    # fidelity exports. Fonts are embedded for non-Latin evidence where available.
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Preformatted
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from pathlib import Path
    data=io.BytesIO();styles=getSampleStyleSheet();font=Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
    if font.exists():
        pdfmetrics.registerFont(TTFont('ZEUS',str(font)));styles['Code'].fontName='ZEUS';styles['BodyText'].fontName='ZEUS'
    styles['Code'].fontSize=7;styles['Code'].leading=10;styles['Code'].textColor=colors.HexColor('#18382b')
    story=[Paragraph('ZEUS Security Report',styles['Title']),Paragraph('Confirmed findings, observations and unresolved results must be interpreted separately. Full structured evidence is in the accompanying JSON/HTML export.',styles['BodyText']),Spacer(1,18)]
    for key in ('artifact','inventory','findings','coverage','runtime_correlations'):
        story.append(Paragraph(html.escape(key.replace('_',' ').title()),styles['Heading2']))
        text=json.dumps(report.get(key,{}),ensure_ascii=False,indent=2)
        # Bound PDF size; JSON is the complete authoritative structured export.
        if len(text)>40000:text=text[:40000]+'\n[Section truncated in PDF; see JSON export]'
        lines=[]
        for line in text.splitlines():lines.extend(line[i:i+105] for i in range(0,max(1,len(line)),105))
        story.extend([Preformatted('\n'.join(lines),styles['Code']),Spacer(1,14)])
    SimpleDocTemplate(data,title='ZEUS Security Report',author='ZEUS',leftMargin=35,rightMargin=35).build(story)
    return data.getvalue()


def export(report, format):
    if format=='json':return json.dumps(report,ensure_ascii=False,indent=2).encode(),'application/json'
    if format=='html':return render_html(report),'text/html; charset=utf-8'
    if format=='pdf':return render_pdf(report),'application/pdf'
    raise ValueError('Export format must be json, html or pdf')
