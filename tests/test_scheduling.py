import json
import tempfile
import unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
from sentinel import scheduling,server
from sentinel.core import initialize


class ScheduleTests(unittest.TestCase):
    def test_uses_scan_event_not_historical_timezone_recurrence(self):
        text='BEGIN:VCALENDAR\nBEGIN:VTIMEZONE\nRRULE:FREQ=YEARLY\nEND:VTIMEZONE\nBEGIN:VEVENT\nDTSTART;TZID=/freeassociation.sourceforge.net/America/New_York:\n 20261101T020000\nRRULE:FREQ=WEEKLY\nEND:VEVENT\nEND:VCALENDAR'
        data=scheduling.describe(text,current=datetime(2026,10,31,tzinfo=timezone.utc))
        self.assertEqual(data['recurrence'],'weekly')
        self.assertEqual(data['start_local'],'2026-11-01T02:00')
        self.assertEqual(data['next_run'],'2026-11-01T02:00:00-05:00')

    def test_rejects_missing_ambiguous_and_past_local_times(self):
        current=datetime(2026,1,1,tzinfo=timezone.utc)
        for value in ('2026-03-08T02:30','2026-11-01T01:30','2025-01-01T12:00','invalid'):
            with self.subTest(value=value),self.assertRaises(ValueError):scheduling.parse_start(value,current)

    def test_daily_recurrence_skips_nonexistent_dst_time(self):
        start=scheduling.parse_start('2026-03-07T02:30',datetime(2026,1,1,tzinfo=timezone.utc))
        text=scheduling.calendar(start,'daily')
        data=scheduling.describe(text,current=datetime(2026,3,8,5,tzinfo=timezone.utc))
        self.assertEqual(data['next_run'],'2026-03-09T02:30:00-04:00')

    def test_once_has_no_recurrence_rule_and_expires(self):
        start=scheduling.parse_start('2026-12-01T12:00',datetime(2026,1,1,tzinfo=timezone.utc))
        text=scheduling.calendar(start,'once')
        self.assertNotIn('RRULE',text)
        self.assertIsNone(scheduling.describe(text,current=datetime(2026,12,2,tzinfo=timezone.utc))['next_run'])

    def test_create_schedule_is_deferred_and_keeps_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db';initialize(path)
            with patch.object(server,'DB',path),patch.object(server.engine,'create_assessment',return_value={'task_id':'task','schedule_id':'schedule'}) as create:
                result=server.save_scan_schedule({'name':'IoT evening','scope':'192.168.20.0/24','start':'2030-01-01T20:00','recurrence':'daily','profile':'Full and fast'})
                self.assertFalse(create.call_args.kwargs['start_now'])
                self.assertEqual(create.call_args.args[0],'192.168.20.0/24')
                self.assertEqual(result['segments'],['IoT'])
                with patch.object(server.engine,'disable_schedule') as disable:
                    server.set_scan_schedule_enabled('task',False);disable.assert_called_once_with('task')
                with patch.object(server.engine,'attach_schedule') as enable:
                    server.set_scan_schedule_enabled('task',True);enable.assert_called_once_with('task','schedule','daily')

    def test_edit_cannot_silently_change_scan_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'state.db';initialize(path)
            with patch.object(server,'DB',path),patch.object(server.engine,'create_assessment',return_value={'task_id':'task','schedule_id':'schedule'}):
                server.save_scan_schedule({'scope':'192.168.10.0/24','start':'2030-01-01T20:00','recurrence':'weekly'})
                with self.assertRaisesRegex(ValueError,'new schedule'):
                    server.save_scan_schedule({'task_id':'task','scope':'192.168.20.0/24','start':'2030-01-01T20:00','recurrence':'weekly'})
