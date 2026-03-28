from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import re


@dataclass
class BlacklistEntry:
    value: str
    entry_type: str
    source: str
    created_at: datetime

    IP_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    @staticmethod
    def parse(line: str) -> Optional["BlacklistEntry"]:
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        parts = line.split("|")
        value = parts[0].strip()
        entry_type = parts[1].strip() if len(parts) > 1 else BlacklistEntry.guess_type(value)
        source = parts[2].strip() if len(parts) > 2 else "file"
        created_str = parts[3].strip() if len(parts) > 3 else ""
        
        try:
            created_at = datetime.fromisoformat(created_str) if created_str else datetime.now()
        except ValueError:
            created_at = datetime.now()

        if not value:
            return None

        return BlacklistEntry(
            value=value,
            entry_type=entry_type,
            source=source,
            created_at=created_at
        )

    @staticmethod
    def guess_type(value: str) -> str:
        if BlacklistEntry.IP_PATTERN.match(value):
            return "ip"
        if BlacklistEntry.DOMAIN_PATTERN.match(value):
            return "domain"
        return "unknown"

    @staticmethod
    def validate(value: str) -> bool:
        if BlacklistEntry.IP_PATTERN.match(value):
            return True
        if BlacklistEntry.DOMAIN_PATTERN.match(value):
            return True
        return False

    def to_line(self) -> str:
        return f"{self.value}|{self.entry_type}|{self.source}|{self.created_at.isoformat()}"
