import csv
import json
from typing import List
from datetime import datetime

from src.models.event import SysmonEvent


class ReportExporter:

    @staticmethod
    def export_csv(events: List[SysmonEvent], filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(SysmonEvent.csv_headers())
                for event in events:
                    writer.writerow(event.to_csv_row())
            return True
        except Exception:
            return False

    @staticmethod
    def export_json(events: List[SysmonEvent], filepath: str) -> bool:
        try:
            data = {
                "export_time": datetime.now().isoformat(),
                "total_events": len(events),
                "events": [event.to_dict() for event in events]
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception:
            return False

    @staticmethod
    def export_malicious_only(events: List[SysmonEvent], filepath: str, format: str = "csv") -> bool:
        malicious_events = [e for e in events if e.is_malicious]
        if not malicious_events:
            return False
        
        if format.lower() == "json":
            return ReportExporter.export_json(malicious_events, filepath)
        else:
            return ReportExporter.export_csv(malicious_events, filepath)
