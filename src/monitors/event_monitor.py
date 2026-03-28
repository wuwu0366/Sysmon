import time
from typing import Optional
from datetime import datetime

from PyQt5.QtCore import QThread, pyqtSignal

try:
    import win32evtlog
    import win32con
    import win32api
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

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
        self._batch_interval_ms = 100
        self._handle = None

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
            if HAS_WIN32:
                self._handle = win32evtlog.OpenEventLog(None, self.channel)
            self.start()

    def stop_monitoring(self):
        self._running = False
        if self._handle:
            win32evtlog.CloseEventLog(self._handle)
            self._handle = None
        self.wait()

    def pause_monitoring(self):
        self._paused = True

    def resume_monitoring(self):
        self._paused = False

    def _query_events(self):
        if not HAS_WIN32 or not self._handle:
            return []

        try:
            flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_FORWARDS_READ
            
            events = []
            while True:
                records = win32evtlog.ReadEventLog(self._handle, flags, 0)
                if not records:
                    break

                for record in records:
                    if record.RecordNumber <= self._last_record_id:
                        continue

                    try:
                        event = self._parse_record(record)
                        if event:
                            events.append(event)
                            if event.timestamp:
                                self._last_record_id = record.RecordNumber
                    except Exception:
                        continue

                if len(records) < 10:
                    break
                    
            return events
        except Exception:
            return []

    def _parse_record(self, record):
        try:
            event_xml = getattr(record, 'Xml', None)
            if not event_xml:
                try:
                    event_xml = record.StringInsertions
                    if event_xml:
                        event_xml = str(event_xml)
                except Exception:
                    pass
                    
            if not event_xml:
                return None
                
            return self._parser.parse_event(event_xml)
        except Exception:
            return None

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
