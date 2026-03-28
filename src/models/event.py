from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SysmonEvent:
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    dest_hostname: str
    protocol: str
    process_name: str
    process_path: str
    process_id: int
    user: str
    is_malicious: bool = False
    matched_entry: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "dest_hostname": self.dest_hostname,
            "protocol": self.protocol,
            "process_name": self.process_name,
            "process_path": self.process_path,
            "process_id": self.process_id,
            "user": self.user,
            "is_malicious": self.is_malicious,
            "matched_entry": self.matched_entry,
        }

    def to_csv_row(self) -> list:
        return [
            self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            self.source_ip,
            str(self.source_port),
            self.dest_ip,
            str(self.dest_port),
            self.dest_hostname,
            self.protocol,
            self.process_name,
            self.process_path,
            str(self.process_id),
            self.user,
            "恶意" if self.is_malicious else "正常",
            self.matched_entry,
        ]

    @staticmethod
    def csv_headers() -> list:
        return [
            "时间", "源IP", "源端口", "目的IP", "目的端口",
            "目的域名", "协议", "进程名", "进程路径", "PID",
            "用户", "判定", "匹配条目"
        ]


@dataclass
class MatchResult:
    ip_matched: bool = False
    domain_matched: bool = False
    is_malicious: bool = False
    matched_entry: str = ""


@dataclass
class DisplayEvent:
    event: SysmonEvent
    is_expanded: bool = False
    is_malicious: bool = False
