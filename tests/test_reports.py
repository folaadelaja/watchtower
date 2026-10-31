import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from sentinel import server
from sentinel.core import connect, initialize, severity_band


class ReportImportTests(unittest.TestCase):
    def test_completed_report_imports_findings_and_is_idempotent(self):
        summary=ET.fromstring('<get_reports_response><report id="report-1"><task><name>Test scan</name></task><report><scan_run_status>Done</scan_run_status><scan_start>2026-10-31T12:00:00Z</scan_start><scan_end>2026-10-31T12:05:00Z</scan_end></report></report></get_reports_response>')
        detail=ET.fromstring('<get_reports_response><report><report><results><result><host>192.168.10.30</host><port>8443/tcp</port><name>Example finding</name><severity>5.0</severity><description>Evidence</description><nvt oid="example"><tags>solution=Apply the fix</tags></nvt></result></results></report></report></get_reports_response>')
        class Client:
            def request(self, element):
                return detail if element.get('details')=='1' else summary
        @contextmanager
        def session():yield Client()
        with tempfile.TemporaryDirectory() as directory:
            db=Path(directory)/'state.db';initialize(db)
            with patch.object(server,'DB',db),patch.object(server.engine,'session',session):
                server.import_reports();server.import_reports()
            with connect(db) as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM findings').fetchone()[0],1)
                self.assertEqual(connection.execute('SELECT count(*) FROM reports').fetchone()[0],1)
                self.assertEqual(connection.execute('SELECT solution FROM findings').fetchone()[0],'Apply the fix')
                self.assertEqual(connection.execute('SELECT count(*) FROM report_findings').fetchone()[0],1)

    def test_severity_boundaries(self):
        self.assertEqual([severity_band(s) for s in [9,7,4,.1,0,-1]],['Critical','High','Medium','Low','Informational','Unrated'])

    def test_distinct_native_results_for_same_check_are_preserved(self):
        summary=ET.fromstring('<get_reports_response><report id="report"><report><scan_run_status>Done</scan_run_status></report></report></get_reports_response>')
        results=''.join(f'<result id="{identifier}"><host>192.168.10.30</host><port>443/tcp</port><name>TLS check</name><severity>5</severity><description>{identifier}</description><nvt oid="same-check"/></result>' for identifier in ('one','two','one'))
        detail=ET.fromstring('<get_reports_response><report><results>'+results+'</results></report></get_reports_response>')
        class Client:
            def request(self, element):return detail if element.get('details')=='1' else summary
        @contextmanager
        def session():yield Client()
        with tempfile.TemporaryDirectory() as directory:
            db=Path(directory)/'state.db';initialize(db)
            with patch.object(server,'DB',db),patch.object(server.engine,'session',session):
                server.import_reports()
                self.assertEqual(server.report_view('report')['total'],2)

    def test_report_snapshots_scope_cves_and_filtered_exports(self):
        current={'id':'first','score':'9.8','name':'First observation'}
        class Client:
            def request(self, element):
                if element.tag=='get_targets':return ET.fromstring('<get_targets_response><target><hosts>192.168.10.0/24</hosts></target></get_targets_response>')
                if element.get('details')=='1':
                    return ET.fromstring(f'<get_reports_response><report><report><task><target id="target"/></task><results><result><host>192.168.10.30</host><port>443/tcp</port><name>{current["name"]}</name><severity>{current["score"]}</severity><description>Evidence</description><nvt oid="same-check"><refs><ref type="cve" id="CVE-2024-12345"/><ref type="url" id="https://example.test"/></refs><tags>solution=Fix</tags></nvt></result></results></report></report></get_reports_response>')
                return ET.fromstring(f'<get_reports_response><report id="{current["id"]}"><task id="task"><name>LAN assessment</name></task><report><scan_run_status>Done</scan_run_status><scan_end>2026-10-31T12:00:00Z</scan_end></report></report></get_reports_response>')
        @contextmanager
        def session():yield Client()
        with tempfile.TemporaryDirectory() as directory:
            db=Path(directory)/'state.db';initialize(db)
            with patch.object(server,'DB',db),patch.object(server.engine,'session',session):
                server.import_reports()
                current.update(id='second',score='2.0',name='Later observation')
                server.import_reports()
                first=server.report_view('first','Critical','CVE-2024-12345')
                second=server.report_view('second')
                self.assertEqual(first['report']['scope'],'192.168.10.0/24')
                self.assertEqual(first['report']['segments'],['LAN'])
                self.assertEqual(first['findings'][0]['name'],'First observation')
                self.assertEqual(first['findings'][0]['cves'],['CVE-2024-12345'])
                self.assertEqual(first['severity_counts']['Critical'],1)
                self.assertEqual(second['findings'][0]['severity_category'],'Low')
                self.assertEqual(server.report_view('second','Critical')['filtered_count'],0)
                exported=server.report_export_rows(first)
                self.assertEqual(exported[0]['severity_category'],'Critical')
                self.assertEqual(exported[0]['scope'],'192.168.10.0/24')
                self.assertEqual(exported[0]['cves'],'CVE-2024-12345')
                self.assertEqual(server.report_view('first','All','no-match')['filtered_count'],0)
