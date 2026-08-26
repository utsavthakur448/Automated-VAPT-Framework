from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

class PDFReportGenerator:

    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._create_styles()

    def _create_styles(self):
        self.styles.add(ParagraphStyle(name='NexusTitle', parent=self.styles['Title'], fontName='Helvetica-Bold', fontSize=24, leading=28, alignment=TA_CENTER, textColor=colors.HexColor('#00A8E8'), spaceAfter=8))
        self.styles.add(ParagraphStyle(name='NexusSubtitle', parent=self.styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, alignment=TA_CENTER, textColor=colors.HexColor('#4B5563'), spaceAfter=6))
        self.styles.add(ParagraphStyle(name='NexusSection', parent=self.styles['Heading1'], fontName='Helvetica-Bold', fontSize=15, leading=18, textColor=colors.HexColor('#17324D'), spaceBefore=4, spaceAfter=8))
        self.styles.add(ParagraphStyle(name='NexusSubSection', parent=self.styles['Heading2'], fontName='Helvetica-Bold', fontSize=10, leading=13, textColor=colors.HexColor('#24506F'), spaceBefore=5, spaceAfter=5))
        self.styles.add(ParagraphStyle(name='NexusBody', parent=self.styles['BodyText'], fontName='Helvetica', fontSize=8.5, leading=12, textColor=colors.HexColor('#222222')))
        self.styles.add(ParagraphStyle(name='NexusFinding', parent=self.styles['BodyText'], fontName='Helvetica-Bold', fontSize=10, leading=13, textColor=colors.HexColor('#17324D'), spaceAfter=4))
        self.styles.add(ParagraphStyle(name='NexusFooter', parent=self.styles['Normal'], fontName='Helvetica', fontSize=7, alignment=TA_CENTER, textColor=colors.grey))

    @staticmethod
    def _value(obj, key, default=''):
        if obj is None:
            return default
        if isinstance(obj, dict):
            value = obj.get(key, default)
        else:
            value = getattr(obj, key, default)
        if value is None:
            return default
        return value

    @staticmethod
    def _escape(value):
        if value is None:
            return ''
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def _paragraph(self, text, style='NexusBody'):
        return Paragraph(self._escape(text), self.styles[style])

    @staticmethod
    def _severity_color(severity):
        severity = str(severity or 'INFO').upper()
        return {'CRITICAL': colors.HexColor('#B91C1C'), 'HIGH': colors.HexColor('#C2410C'), 'MEDIUM': colors.HexColor('#B45309'), 'LOW': colors.HexColor('#2563EB'), 'INFO': colors.HexColor('#4B5563')}.get(severity, colors.HexColor('#4B5563'))

    def _section_header(self, number, title):
        table = Table([[Paragraph(f'{number}. {self._escape(title)}', self.styles['NexusSection'])]], colWidths=[180 * mm])
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EAF4FA')), ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#00A8E8')), ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 2)]))
        return [Spacer(1, 2 * mm), table, Spacer(1, 3 * mm)]

    def _section_end(self, title):
        table = Table([[Paragraph(f'END OF {self._escape(title).upper()}', self.styles['NexusFooter'])]], colWidths=[180 * mm])
        table.setStyle(TableStyle([('LINEABOVE', (0, 0), (-1, 0), 0.6, colors.HexColor('#9AA7B2')), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
        return [Spacer(1, 3 * mm), table, Spacer(1, 4 * mm)]

    def _info_table(self, rows, label_width=48 * mm):
        table = Table(rows, colWidths=[label_width, 180 * mm - label_width])
        table.setStyle(TableStyle([('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E8EEF5')), ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'), ('FONTNAME', (1, 0), (1, -1), 'Helvetica'), ('FONTSIZE', (0, 0), (-1, -1), 8), ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#AAB4BE')), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 6), ('RIGHTPADDING', (0, 0), (-1, -1), 6), ('TOPPADDING', (0, 0), (-1, -1), 5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
        return table

    def _page_header_footer(self, canvas, document):
        canvas.saveState()
        width, height = A4
        if document.page > 1:
            canvas.setFillColor(colors.HexColor('#17324D'))
            canvas.rect(0, height - 8 * mm, width, 8 * mm, fill=1, stroke=0)
            canvas.setFillColor(colors.white)
            canvas.setFont('Helvetica-Bold', 7)
            canvas.drawString(15 * mm, height - 5.2 * mm, 'VULNSCOPE | SECURITY ASSESSMENT REPORT')
        canvas.setStrokeColor(colors.HexColor('#D1D5DB'))
        canvas.line(15 * mm, 14 * mm, width - 15 * mm, 14 * mm)
        canvas.setFillColor(colors.grey)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(15 * mm, 9 * mm, 'VULNSCOPE | Developed by Utsav Thakur')
        canvas.drawRightString(width - 15 * mm, 9 * mm, f'Page {document.page}')
        canvas.restoreState()

    def _executive_summary(self, target, risk_summary, findings):
        elements = []
        elements.extend(self._section_header(1, 'Executive Summary'))
        overall_risk = str(self._value(risk_summary, 'risk_rating', 'UNKNOWN')).upper()
        risk_score = self._value(risk_summary, 'risk_score', 0.0)
        total_findings = len(findings or [])
        text = f'VULNSCOPE performed an automated vulnerability assessment against the authorized target {target}. The assessment combined network service discovery, vulnerability detection, web security checks, evidence collection, and risk prioritization.'
        elements.append(self._paragraph(text))
        elements.append(Spacer(1, 5 * mm))
        rows = [['Target', str(target)], ['Overall Risk', overall_risk], ['Risk Score', str(risk_score)], ['Total Findings', str(total_findings)]]
        table = self._info_table(rows)
        table.setStyle(TableStyle([('TEXTCOLOR', (1, 1), (1, 1), self._severity_color(overall_risk)), ('FONTNAME', (1, 1), (1, 1), 'Helvetica-Bold')]))
        elements.append(table)
        elements.append(Spacer(1, 5 * mm))
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings or []:
            severity = str(self._value(finding, 'severity', 'INFO')).upper()
            if severity in counts:
                counts[severity] += 1
        severity_rows = [['Severity', 'Count']]
        for severity in counts:
            severity_rows.append([severity, str(counts[severity])])
        severity_table = Table(severity_rows, colWidths=[90 * mm, 90 * mm], repeatRows=1)
        severity_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#26384A')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('GRID', (0, 0), (-1, -1), 0.4, colors.grey), ('ALIGN', (1, 1), (1, -1), 'CENTER')]))
        for row, severity in enumerate(counts.keys(), start=1):
            severity_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), self._severity_color(severity)), ('FONTNAME', (0, row), (0, row), 'Helvetica-Bold')]))
        elements.append(severity_table)
        elements.extend(self._section_end('Executive Summary'))
        return elements

    def _target_information(self, scan_result):
        elements = []
        elements.extend(self._section_header(2, 'Target Information'))
        assets = getattr(scan_result, 'assets', []) or []
        if not assets:
            elements.append(self._paragraph('No target assets were discovered.'))
            elements.extend(self._section_end('Target Information'))
            return elements
        for asset in assets:
            hostname = self._value(asset, 'hostname', '')
            if not hostname:
                hostname = 'Not resolved'
            rows = [['Host', self._value(asset, 'host', 'Unknown')], ['Status', self._value(asset, 'status', 'Unknown')], ['Hostname', hostname], ['MAC Address', self._value(asset, 'mac_address', '') or 'N/A'], ['Vendor', self._value(asset, 'vendor', '') or 'N/A'], ['Operating System', self._value(asset, 'os_name', '') or 'N/A'], ['OS Family', self._value(asset, 'os_family', '') or 'N/A'], ['OS Generation', self._value(asset, 'os_generation', '') or 'N/A'], ['OS Accuracy', self._value(asset, 'os_accuracy', '') or 'N/A']]
            elements.append(self._info_table(rows))
            elements.append(Spacer(1, 5 * mm))
        elements.extend(self._section_end('Target Information'))
        return elements

    def _nmap_discovery(self, scan_result):
        elements = []
        elements.extend(self._section_header(3, 'Nmap Discovery'))
        assets = getattr(scan_result, 'assets', []) or []
        host_count = len(assets)
        port_count = 0
        for asset in assets:
            ports = getattr(asset, 'open_ports', []) or []
            port_count += len(ports)
        summary = [['Hosts discovered', str(host_count)], ['Open ports', str(port_count)]]
        elements.append(self._info_table(summary))
        elements.append(Spacer(1, 5 * mm))
        for asset in assets:
            host = self._value(asset, 'host', 'Unknown')
            elements.append(Paragraph(f'Host: {self._escape(host)}', self.styles['NexusSubSection']))
            rows = [['PORT', 'STATE', 'SERVICE', 'PRODUCT', 'VERSION']]
            ports = getattr(asset, 'open_ports', []) or []
            for port in ports:
                rows.append([str(self._value(port, 'number', '')), str(self._value(port, 'state', '')), str(self._value(port, 'service', '')), str(self._value(port, 'product', '')), str(self._value(port, 'version', ''))])
            if len(rows) == 1:
                rows.append(['-', '-', 'No open ports', '', ''])
            table = Table(rows, repeatRows=1, colWidths=[18 * mm, 20 * mm, 30 * mm, 45 * mm, 67 * mm])
            table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#26384A')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, -1), 6.5), ('GRID', (0, 0), (-1, -1), 0.3, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F4F6F8')]), ('LEFTPADDING', (0, 0), (-1, -1), 3), ('RIGHTPADDING', (0, 0), (-1, -1), 3)]))
            elements.append(table)
            elements.append(Spacer(1, 6 * mm))
        elements.extend(self._section_end('Nmap Discovery'))
        return elements

    def _finding_block(self, finding, number=None):
        elements = []
        title = self._value(finding, 'title', 'Untitled Finding')
        if number is not None:
            title = f'{number}. {title}'
        severity = str(self._value(finding, 'severity', 'INFO')).upper()
        elements.append(Paragraph(self._escape(title), self.styles['NexusFinding']))
        host = self._value(finding, 'host', 'Unknown')
        port = self._value(finding, 'port', '')
        location = str(host)
        if port not in ('', None):
            location += f':{port}/tcp'
        rows = [['Severity', severity], ['Host', location]]
        cve = self._value(finding, 'cve', '')
        if cve:
            rows.append(['CVE', str(cve)])
        cvss = self._value(finding, 'cvss', '')
        if cvss not in ('', None):
            rows.append(['CVSS', str(cvss)])
        detection = self._value(finding, 'detection', '')
        if detection:
            rows.append(['Detection', str(detection)])
        confidence = self._value(finding, 'confidence', '')
        if confidence:
            rows.append(['Confidence', str(confidence)])
        priority = self._value(finding, 'priority', '')
        if priority:
            rows.append(['Priority', str(priority)])
        table = self._info_table(rows, label_width=40 * mm)
        table.setStyle(TableStyle([('TEXTCOLOR', (1, 0), (1, 0), self._severity_color(severity)), ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold')]))
        elements.append(table)
        elements.append(Spacer(1, 3 * mm))
        for heading, key in [('Description', 'description'), ('Evidence', 'evidence'), ('Remediation', 'remediation')]:
            value = self._value(finding, key, '')
            if not value:
                continue
            elements.append(Paragraph(heading, self.styles['NexusSubSection']))
            elements.append(self._paragraph(value))
        elements.append(Spacer(1, 6 * mm))
        return elements

    def _vulnerability_assessment(self, findings):
        elements = []
        elements.extend(self._section_header(4, 'Vulnerability Assessment'))
        findings = findings or []
        if not findings:
            elements.append(self._paragraph('No network vulnerability findings were identified.'))
            elements.extend(self._section_end('Vulnerability Assessment'))
            return elements
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        counts = {severity: 0 for severity in severity_order}
        for finding in findings:
            severity = str(self._value(finding, 'severity', 'INFO')).upper()
            if severity in counts:
                counts[severity] += 1
        rows = [['Severity', 'Count']]
        for severity in severity_order:
            rows.append([severity, str(counts[severity])])
        summary_table = Table(rows, colWidths=[90 * mm, 90 * mm], repeatRows=1)
        summary_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#26384A')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('GRID', (0, 0), (-1, -1), 0.4, colors.grey), ('ALIGN', (1, 1), (1, -1), 'CENTER')]))
        for row, severity in enumerate(severity_order, start=1):
            summary_table.setStyle(TableStyle([('TEXTCOLOR', (0, row), (0, row), self._severity_color(severity)), ('FONTNAME', (0, row), (0, row), 'Helvetica-Bold')]))
        elements.append(summary_table)
        elements.append(Spacer(1, 5 * mm))
        ordered = []
        for severity in severity_order:
            ordered.extend([finding for finding in findings if str(self._value(finding, 'severity', 'INFO')).upper() == severity])
        for number, finding in enumerate(ordered, start=1):
            elements.extend(self._finding_block(finding, number))
        elements.extend(self._section_end('Vulnerability Assessment'))
        return elements

    def _web_security(self, findings):
        elements = []
        elements.extend(self._section_header(5, 'Web Security Assessment'))
        findings = findings or []
        if not findings:
            elements.append(self._paragraph('No web security findings were identified.'))
            elements.extend(self._section_end('Web Security Assessment'))
            return elements
        elements.append(self._paragraph(f'Total Web Findings: {len(findings)}'))
        elements.append(Spacer(1, 4 * mm))
        for number, finding in enumerate(findings, start=1):
            elements.extend(self._finding_block(finding, number))
        elements.extend(self._section_end('Web Security Assessment'))
        return elements

    def _risk_assessment(self, risk_summary, prioritized_findings, findings):
        elements = []
        elements.extend(self._section_header(6, 'Final Risk Assessment'))
        findings = findings or []
        prioritized_findings = prioritized_findings or []
        overall_risk = str(self._value(risk_summary, 'risk_rating', 'UNKNOWN')).upper()
        risk_score = self._value(risk_summary, 'risk_score', 0.0)
        rows = [['Overall Risk', overall_risk], ['Risk Score', str(risk_score)], ['Total Findings', str(len(findings))]]
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for finding in findings:
            severity = str(self._value(finding, 'severity', 'INFO')).upper()
            if severity in counts:
                counts[severity] += 1
        for severity in counts:
            rows.append([severity, str(counts[severity])])
        table = self._info_table(rows, label_width=55 * mm)
        table.setStyle(TableStyle([('TEXTCOLOR', (1, 0), (1, 0), self._severity_color(overall_risk)), ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold')]))
        elements.append(table)
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph('Risk Interpretation', self.styles['NexusSubSection']))
        if overall_risk == 'CRITICAL':
            interpretation = 'Critical-risk findings were identified. Immediate remediation should be prioritized for critical and high-severity findings.'
        elif overall_risk == 'HIGH':
            interpretation = 'High-risk findings were identified. Critical and high-severity findings should receive priority remediation.'
        elif overall_risk == 'MEDIUM':
            interpretation = 'The assessment identified a moderate security risk. Medium and higher severity findings should be addressed according to business impact.'
        elif overall_risk == 'LOW':
            interpretation = 'The assessment identified lower-severity security issues. Remediation should focus on configuration and hardening weaknesses.'
        elif overall_risk in ('NO FINDINGS', 'INFORMATIONAL'):
            interpretation = 'No material vulnerability findings were identified by the configured assessment checks.'
        else:
            interpretation = 'The overall risk could not be classified from the available assessment data.'
        elements.append(self._paragraph(interpretation))
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph('Top Priorities', self.styles['NexusSubSection']))
        valid_priorities = []
        for item in prioritized_findings:
            if not isinstance(item, dict):
                continue
            finding = item.get('finding')
            if finding is None:
                continue
            valid_priorities.append(item)
        if not valid_priorities:
            elements.append(self._paragraph('No prioritized findings are available.'))
        else:
            for number, item in enumerate(valid_priorities[:5], start=1):
                finding = item['finding']
                title = self._value(finding, 'title', 'Untitled Finding')
                severity = str(self._value(finding, 'severity', 'INFO')).upper()
                host = self._value(finding, 'host', 'Unknown')
                port = self._value(finding, 'port', '')
                location = str(host)
                if port not in ('', None):
                    location += f':{port}/tcp'
                cve = self._value(finding, 'cve', '')
                cvss = self._value(finding, 'cvss', '')
                risk_score_value = item.get('risk_score', 0.0)
                priority = item.get('priority', 'INFORMATIONAL')
                elements.append(Paragraph(f'{number}. {self._escape(title)}', self.styles['NexusFinding']))
                priority_rows = [['Host', location]]
                if cve:
                    priority_rows.append(['CVE', str(cve)])
                if cvss not in ('', None):
                    priority_rows.append(['CVSS', str(cvss)])
                priority_rows.extend([['Risk Score', str(risk_score_value)], ['Priority', str(priority)]])
                priority_table = self._info_table(priority_rows, label_width=40 * mm)
                priority_table.setStyle(TableStyle([('TEXTCOLOR', (1, 0), (1, 0), self._severity_color(severity)), ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold')]))
                elements.append(priority_table)
                elements.append(Spacer(1, 4 * mm))
        elements.extend(self._section_end('Final Risk Assessment'))
        return elements

    def _methodology(self):
        elements = []
        elements.extend(self._section_header(7, 'Assessment Methodology'))
        text = "The assessment was performed using VULNSCOPE's automated assessment workflow. The process included target validation, Nmap-based service discovery, service-specific vulnerability detection, CVE/CPE matching, web security checks, evidence collection, severity classification, and risk prioritization."
        elements.append(self._paragraph(text))
        elements.extend(self._section_end('Assessment Methodology'))
        return elements

    def _conclusion(self, risk_summary, findings):
        elements = []
        elements.extend(self._section_header(8, 'Conclusion'))
        findings = findings or []
        overall_risk = str(self._value(risk_summary, 'risk_rating', 'UNKNOWN')).upper()
        if findings:
            text = f'The assessment identified security findings requiring remediation. The calculated overall risk level is {overall_risk}. Critical and high severity findings should receive priority attention, followed by medium and lower severity findings.'
        else:
            text = f'The assessment did not identify findings through the configured checks. The calculated overall risk level is {overall_risk}. Continued security monitoring and periodic reassessment are recommended.'
        elements.append(self._paragraph(text))
        elements.append(Spacer(1, 5 * mm))
        elements.append(self._paragraph('This report is intended for authorized security assessment and remediation purposes.'))
        elements.extend(self._section_end('Conclusion'))
        return elements

    def generate(self, target, scan_result, findings, network_findings, web_findings, risk_summary, prioritized_findings):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = str(target).replace('/', '_').replace('\\', '_').replace(':', '_').replace('?', '_').replace('&', '_')
        filename = f'VULNSCOPE_Report_{safe_target}_{timestamp}.pdf'
        output_path = self.output_dir / filename
        document = SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=15 * mm, leftMargin=15 * mm, topMargin=17 * mm, bottomMargin=18 * mm, title='VULNSCOPE Security Assessment Report', author='Utsav Thakur - VULNSCOPE', subject='Automated Vulnerability Assessment Report')
        story = []
        story.append(Spacer(1, 20 * mm))
        cover = Table([[Paragraph('VULNSCOPE', self.styles['NexusTitle'])]], colWidths=[180 * mm])
        cover.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F2FAFD')), ('BOX', (0, 0), (-1, -1), 1.2, colors.HexColor('#00A8E8')), ('TOPPADDING', (0, 0), (-1, -1), 12), ('BOTTOMPADDING', (0, 0), (-1, -1), 5)]))
        story.append(cover)
        story.append(Paragraph('Security Assessment Report', self.styles['NexusTitle']))
        story.append(Paragraph(f'Target: {self._escape(target)}', self.styles['NexusSubtitle']))
        story.append(Paragraph(datetime.now().strftime('%d %B %Y, %H:%M:%S'), self.styles['NexusSubtitle']))
        story.append(Spacer(1, 8 * mm))
        author_rows = [['Developed by', 'Utsav Thakur'], ['Email', 'utsavthakur448@gmail.com'], ['LinkedIn', 'https://www.linkedin.com/in/utsavthakur123'], ['GitHub', 'https://github.com/utsavthakur448']]
        author_table = self._info_table(author_rows, label_width=40 * mm)
        story.append(author_table)
        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph('Automated Vulnerability Assessment and Penetration Testing Framework', self.styles['NexusSubtitle']))
        story.append(Spacer(1, 8 * mm))
        authorized = Table([[Paragraph('<b>AUTHORIZED SECURITY ASSESSMENT</b>', self.styles['NexusBody'])]], colWidths=[180 * mm])
        authorized.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FFF7D6')), ('BOX', (0, 0), (-1, -1), 0.8, colors.HexColor('#D4A72C')), ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7)]))
        story.append(authorized)
        story.append(PageBreak())
        story.extend(self._executive_summary(target, risk_summary, findings))
        story.extend(self._target_information(scan_result))
        story.extend(self._nmap_discovery(scan_result))
        story.extend(self._vulnerability_assessment(network_findings))
        story.extend(self._web_security(web_findings))
        story.extend(self._risk_assessment(risk_summary, prioritized_findings, findings))
        story.extend(self._methodology())
        story.extend(self._conclusion(risk_summary, findings))
        document.build(story, onFirstPage=self._page_header_footer, onLaterPages=self._page_header_footer)
        return str(output_path)
