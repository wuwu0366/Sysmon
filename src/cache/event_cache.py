from typing import Callable, Optional, Dict, List
from collections import defaultdict

from src.models.event import SysmonEvent, DisplayEvent


class EventCache:
    MAX_SIZE = 100000
    MALICIOUS_MAX = 5000

    def __init__(self, max_size: int = 100000, malicious_max: int = 5000):
        self._normal_events = []
        self._malicious_events = []
        self._max_size = max_size
        self._malicious_max = malicious_max
        self._index: Dict[str, Dict[str, List[int]]] = defaultdict(lambda: defaultdict(list))
        self._display_list: List[DisplayEvent] = []
        self._dirty = True

    def add(self, event: SysmonEvent):
        display_event = DisplayEvent(event=event, is_expanded=False, is_malicious=event.is_malicious)
        
        if event.is_malicious:
            self._malicious_events.insert(0, event)
            if len(self._malicious_events) > self._malicious_max:
                removed = self._malicious_events.pop()
                self._remove_from_index(removed, len(self._malicious_events))
        else:
            self._normal_events.insert(0, event)
            if len(self._normal_events) > (self._max_size - self._malicious_max):
                self._normal_events.pop()
        
        self._dirty = True

    def _remove_from_index(self, event: SysmonEvent, normal_count: int):
        pass

    def _rebuild_display_list(self):
        if not self._dirty:
            return
        
        self._display_list = []
        
        for event in self._malicious_events:
            self._display_list.append(DisplayEvent(
                event=event,
                is_expanded=False,
                is_malicious=True
            ))
        
        offset = len(self._malicious_events)
        for i, event in enumerate(self._normal_events):
            self._display_list.append(DisplayEvent(
                event=event,
                is_expanded=False,
                is_malicious=False
            ))
        
        self._dirty = False

    def get_all(self) -> List[DisplayEvent]:
        self._rebuild_display_list()
        return self._display_list

    def get_display_order(self) -> List[DisplayEvent]:
        return self.get_all()

    def filter(self, predicate: Callable[[SysmonEvent], bool]) -> List[SysmonEvent]:
        result = []
        for event in self._malicious_events:
            if predicate(event):
                result.append(event)
        for event in self._normal_events:
            if predicate(event):
                result.append(event)
        return result

    def filter_by_field(self, field: str, value: str, exact: bool = False) -> List[DisplayEvent]:
        self._rebuild_display_list()
        result = []
        for de in self._display_list:
            event = de.event
            field_value = ""
            if field == "source_ip":
                field_value = event.source_ip
            elif field == "dest_ip":
                field_value = event.dest_ip
            elif field == "dest_hostname":
                field_value = event.dest_hostname
            elif field == "process_name":
                field_value = event.process_name
            elif field == "protocol":
                field_value = event.protocol
            elif field == "user":
                field_value = event.user
            
            if field_value:
                if exact:
                    if field_value.lower() == value.lower():
                        result.append(de)
                else:
                    if value.lower() in field_value.lower():
                        result.append(de)
        return result

    def search(self, query: str, exact: bool = False) -> List[DisplayEvent]:
        self._rebuild_display_list()
        result = []
        query_lower = query.lower()
        
        for de in self._display_list:
            event = de.event
            if (query_lower in event.source_ip.lower() or
                query_lower in event.dest_ip.lower() or
                query_lower in event.dest_hostname.lower() or
                query_lower in event.process_name.lower() or
                query_lower in event.protocol.lower() or
                query_lower in event.user.lower()):
                result.append(de)
        
        return result

    def get_malicious_only(self) -> List[DisplayEvent]:
        self._rebuild_display_list()
        return [de for de in self._display_list if de.is_malicious]

    def clear(self):
        self._normal_events.clear()
        self._malicious_events.clear()
        self._display_list.clear()
        self._index.clear()
        self._dirty = True

    def get_total_count(self) -> int:
        return len(self._malicious_events) + len(self._normal_events)

    def get_malicious_count(self) -> int:
        return len(self._malicious_events)

    def get_normal_count(self) -> int:
        return len(self._normal_events)

    def invalidate(self):
        self._dirty = True
