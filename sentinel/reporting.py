"""Printable report rendering, scoped to one assessment and its current filters."""
from html import escape
from .core import SEVERITY_BANDS


def render(view):
    report=view['report']
    output='<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Watchtower assessment report</title><link rel="stylesheet" href="/report.css"></head><body>'
    output+='<header><p>WATCHTOWER · ASSESSMENT REPORT</p><h1>'+escape(report['task'])+'</h1>'
    output+='<p><strong>Scanned scope:</strong> '+escape(report['scope'])+'</p><p><strong>Completed:</strong> '+escape(report['scan_end'])+'</p></header>'
    output+=f'<p>{view["filtered_count"]} matching findings from {view["total"]} findings recorded in this assessment.</p>'
    output+='<p>Unscanned or unreachable devices remain unassessed. A missing CVE means the scanner did not list a CVE reference for that check.</p><table><tr><th>Severity</th><th>Assessment findings</th></tr>'
    for band in SEVERITY_BANDS:output+='<tr><td>'+band+'</td><td>'+str(view['severity_counts'][band])+'</td></tr>'
    output+='</table>'
    for band in SEVERITY_BANDS:
        findings=[f for f in view['findings'] if f['severity_category']==band]
        if not findings:continue
        output+='<section><h2>'+band+'</h2>'
        for finding in findings:
            output+='<article><h3>'+escape(finding['name'])+'</h3><p><strong>Asset:</strong> '+escape(finding['host'])+' · '+escape(finding['segment'])+' · '+escape(finding['port'])+'</p>'
            output+='<p><strong>Severity:</strong> '+band+' ('+str(finding['severity'])+')</p><p><strong>CVE references:</strong> '+escape(', '.join(finding['cves']) or 'None listed by scanner')+'</p>'
            output+='<h4>Evidence</h4><pre>'+escape(finding['evidence'])+'</pre><h4>Remediation</h4><pre>'+escape(finding['solution'] or 'No remediation guidance supplied by scanner')+'</pre></article>'
        output+='</section>'
    return output+'</body></html>'
