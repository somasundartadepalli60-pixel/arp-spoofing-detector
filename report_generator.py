"""PDF report template and monitoring report. No secrets or payloads are exported."""
from datetime import datetime
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether


def build_report(path, snapshot, *, template=False):
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CellSmall', fontName='Helvetica', fontSize=8, leading=11, wordWrap='CJK'))
    styles['Title'].textColor = colors.HexColor('#163b52')
    styles['Heading2'].textColor = colors.HexColor('#163b52')
    story=[]
    def para(value, style='BodyText'):
        return Paragraph(escape(str(value)).replace('\n','<br/>'), styles[style])
    def section(title, text=None):
        story.extend([Spacer(1,5*mm),para(title,'Heading2')])
        if text: story.append(para(text))
    def table(headers, rows, widths):
        data=[[para(v,'CellSmall') for v in headers]]
        data += [[para(v,'CellSmall') for v in row] for row in rows]
        t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e1edf2')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#ccd7dd')),
            ('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),
            ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
        story.append(t)
    title='ARP Monitoring Report Template' if template else 'ARP Monitoring Report'
    story += [para(title,'Title'),para('Supraja Technologies | Network security observations','Normal'),Spacer(1,6*mm)]
    meta=[('Generated',datetime.now().isoformat(timespec='seconds')),('Prepared by',snapshot.get('operator') or 'Not supplied'),
          ('Capture status',snapshot.get('status','Not started')),('Scope','Saved alerts and latest available ARP tables')]
    table(['Field','Value'],meta,[42*mm,132*mm])
    section('1. Monitoring summary')
    if template:
        story.append(para('Record interface, monitoring host, observation period, reply count, cache scans, alerts and email submissions.'))
    else:
        info=snapshot.get('info',{})
        rows=[('Interface',info.get('interface','Not available')),('Host IPv4',info.get('my_ip','Not available')),
              ('Host MAC',info.get('my_mac','Not available')),
              ('Monitoring started / stopped',f"{snapshot.get('session_start','Not recorded')} / {snapshot.get('session_end','Not recorded')}"),('ARP replies / cache scans',f"{snapshot.get('packets',0)} / {snapshot.get('scans',0)}"),
              ('Application alerts / email submissions',f"{snapshot.get('alerts',0)} / {snapshot.get('emails',0)}"),
              ('Latest cache read',snapshot.get('cache_time','Not read'))]
        table(['Metric','Value'],rows,[65*mm,109*mm])
    section('2. Alert evidence and observed sender details',
        'A claimed IP and changed MAC are evidence of a mapping conflict. They do not prove malicious intent or reveal the sender\'s real IP. Cache observations have no Ethernet-source or packet-target evidence.')
    events=[] if template else snapshot.get('events',[])
    if not events:story.append(para('No saved alerts.' if not template else 'For each alert, record time, claimed IP, expected/changed MAC, Ethernet source, packet target and capture interface.'))
    for index,event in enumerate(events,1):
        fields=[('Time',event.get('time','')),('Claimed / impersonated IP',event.get('spoofed_ip','')),
            ('Expected baseline MAC',event.get('expected_mac','')),('Observed advertised MAC',event.get('spoofed_mac','')),
            ('Ethernet source MAC',event.get('ether_mac','Unknown')),('Real attacker IP',event.get('attacker_ip','Unknown')),
            ('Packet target IP / MAC',f"{event.get('target_ip','Unknown')} / {event.get('target_mac','Unknown')}"),
            ('Interface',event.get('interface',''))]
        story.extend([Spacer(1,4*mm),para(f"Alert {index} - LOCAL DEMO" if event.get('attacker_ip','').startswith('Local demo') else f'Alert {index}','Heading3')]);table(['Evidence','Observed value'],fields,[60*mm,114*mm])
        story[-3:] = [KeepTogether(story[-3:])]
    for number,title,key in [(3,'Trusted baseline','baseline'),(4,'Latest system ARP cache','cache')]:
        section(f'{number}. {title}')
        rows=list(snapshot.get(key,{}).items()) if not template else []
        if rows:table(['IPv4 address','MAC address'],rows,[65*mm,109*mm])
        else:story.append(para('Not captured.' if not template else 'Record IPv4-to-MAC mappings and observation time.'))
    section('5. Investigation and response',
        'Confirm suspicious changes with the network administrator. Check device replacements, address reassignment and router configuration before isolating a device. This application monitors and alerts; it does not block traffic. Passwords and packet payloads are not captured.')
    section('6. Conclusions / analyst notes',snapshot.get('notes') or 'No analyst notes supplied.')
    def footer(canvas,doc):
        canvas.saveState();canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#627782'))
        canvas.drawString(18*mm,12*mm,'ARP Detector | Observation report');canvas.drawRightString(192*mm,12*mm,f'Page {doc.page}');canvas.restoreState()
    doc=SimpleDocTemplate(str(path),pagesize=A4,rightMargin=18*mm,leftMargin=18*mm,topMargin=18*mm,bottomMargin=20*mm,title=title)
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
