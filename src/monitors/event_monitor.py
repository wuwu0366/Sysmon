import time
import subprocess
from typing import Optional, List
from datetime import datetime

from PyQt5.QtCore import QThread, pyqtSignal

from src.parsers.sysmon_parser import SysmonParser
from src.matchers.blacklist_matcher import BlacklistMatcher
from src.cache.event_cache import EventCache
from src.models.event import SysmonEvent


class EventMonitor(QThread):
    signal_new_event = pyqtSignal(SysmonEvent)
    signal_error = pyqtSignal(str)
    signal_stats = pyqtSignal(int, int)
    signal_batch_events = pyqtSignal(list)

    def __init__(self, channel: str = "Microsoft-Windows-Sysmon/Operational"):
        super().__init__()
        self.channel = channel
        self._running = False
        self._paused = False
        self._last_record_id = 0
        self._parser = SysmonParser()
        self._matcher: Optional[BlacklistMatcher] = None
        self._cache: Optional[EventCache] = None
        self._notify_callback = None
        self._poll_interval = 1.0
        self._batch_buffer = []

    def set_matcher(self, matcher: BlacklistMatcher):
        self._matcher = matcher

    def set_cache(self, cache: EventCache):
        self._cache = cache

    def set_notify_callback(self, callback):
        self._notify_callback = callback

    def start_monitoring(self):
        if not self._running:
            self._running = True
            self._paused = False
            self.start()

    def stop_monitoring(self):
        self._running = False
        self.wait()

    def pause_monitoring(self):
        self._paused = True

    def resume_monitoring(self):
        self._paused = False

    def _query_events(self) -> List[SysmonEvent]:
        try:
            ps_script = f'''
$events = Get-WinEvent -LogName "{self.channel}" -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object {{$_.Id -eq 3}}
foreach ($e in $events) {{
    $e.ToXml()
}}
'''
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return []

            xml_events = result.stdout.strip().split('</Event>')
            events = []
            
            for xml_part in xml_events:
                if not xml_part.strip():
                    continue
                xml_full = xml_part + '</Event>'
                try:
                    event = self._parser.parse_event(xml_full)
                    if event:
                        events.append(event)
                except Exception:
                    continue
                    
            return events
        except Exception:
            return []

    def run(self):
        while self._running:
            if not self._paused:
                events = self._query_events()
                
                for event in events:
                    if self._matcher:
                        match_result = self._matcher.match(event)
                        if match_result.is_malicious:
                            event.is_malicious = True
                            event.matched_entry = match_result.matched_entry
                            
                            if self._notify_callback:
                                self._notify_callback(event)

                    if self._cache:
                        self._cache.add(event)

                    self._batch_buffer.append(event)

                if len(self._batch_buffer) >= 10:
                    self.signal_batch_events.emit(self._batch_buffer)
                    self._batch_buffer.clear()

                for event in events:
                    self.signal_new_event.emit(event)

                if self._cache:
                    total = self._cache.get_total_count()
                    malicious = self._cache.get_malicious_count()
                    self.signal_stats.emit(total, malicious)

            time.sleep(self._poll_interval)

        if self._batch_buffer:
            self.signal_batch_events.emit(self._batch_buffer)
