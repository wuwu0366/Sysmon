import re
from datetime import datetime
from typing import Optional
from xml.etree import ElementTree as ET

from src.models.event import SysmonEvent


class SysmonParser:
    EVENT_ID_NETWORK = 3
    EVENT_ID_DNS = 22
    
    FIELD_MAP = {
        "TimeCreated": "timestamp",
        "SourceIp": "source_ip",
        "SourcePort": "source_port",
        "DestinationIp": "dest_ip",
        "DestinationPort": "dest_port",
        "Protocol": "protocol",
        "Image": "process_name",
        "ProcessId": "process_id",
        "User": "user",
        "QueryName": "query_name",
        "QueryResults": "query_results",
    }

    HOSTNAME_FIELDS = ["DestinationHostname", "DestinationHostname", "QueryName", "query_name"]

    @staticmethod
    def parse_event(event_xml: str) -> Optional[SysmonEvent]:
        try:
            root = ET.fromstring(event_xml)
            
            event_id_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
            if event_id_elem is None:
                event_id_elem = root.find(".//EventID")
            
            if event_id_elem is None:
                return None
                
            event_id = int(event_id_elem.text) if event_id_elem.text else 0
            
            if event_id not in (SysmonParser.EVENT_ID_NETWORK, SysmonParser.EVENT_ID_DNS):
                return None

            time_created = None
            time_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            if time_elem is not None:
                time_attr = time_elem.get("SystemTime")
                if time_attr:
                    try:
                        time_created = datetime.fromisoformat(time_attr.replace("Z", "+00:00"))
                    except ValueError:
                        time_created = datetime.now()
            if time_created is None:
                time_created = datetime.now()

            data = {}
            for elem in root.iter():
                for child in elem:
                    tag_name = child.tag
                    if tag_name.endswith("EventID") or tag_name.endswith("TimeCreated"):
                        continue
                    name = child.get("Name") or ""
                    value = child.text or ""
                    
                    for field_key, field_name in SysmonParser.FIELD_MAP.items():
                        if field_key in name or field_name in name.lower():
                            data[field_name] = value
                            break

            def get_field(key: str, default: str = "") -> str:
                return data.get(key, default)

            def get_int_field(key: str, default: int = 0) -> int:
                val = data.get(key, str(default))
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return default

            image_path = ""
            for elem in root.iter():
                for child in elem:
                    name = child.get("Name") or ""
                    if "ImagePath" in name or "ParentImagePath" in name:
                        image_path = child.text or ""
                        break

            if event_id == SysmonParser.EVENT_ID_DNS:
                return SysmonEvent(
                    timestamp=time_created,
                    source_ip=get_field("source_ip"),
                    source_port=get_int_field("source_port"),
                    dest_ip=get_field("query_results"),
                    dest_port=53,
                    dest_hostname=get_field("query_name"),
                    protocol="DNS",
                    process_name=get_field("process_name"),
                    process_path=image_path,
                    process_id=get_int_field("process_id"),
                    user=get_field("user"),
                    event_type="dns",
                    query_name=get_field("query_name"),
                    query_results=get_field("query_results"),
                )

            return SysmonEvent(
                timestamp=time_created,
                source_ip=get_field("source_ip"),
                source_port=get_int_field("source_port"),
                dest_ip=get_field("dest_ip"),
                dest_port=get_int_field("dest_port"),
                dest_hostname=get_field("dest_hostname"),
                protocol=get_field("protocol"),
                process_name=get_field("process_name"),
                process_path=image_path,
                process_id=get_int_field("process_id"),
                user=get_field("user"),
                event_type="network",
            )
        except ET.ParseError:
            return None
        except Exception:
            return None

    @staticmethod
    def parse_csv_line(line: str) -> Optional[SysmonEvent]:
        try:
            if not line.strip():
                return None

            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) < 11:
                return None

            timestamp_str = parts[0]
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str)
                except ValueError:
                    timestamp = datetime.now()

            def safe_int(val: str, default: int = 0) -> int:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return default

            return SysmonEvent(
                timestamp=timestamp,
                source_ip=parts[1],
                source_port=safe_int(parts[2]),
                dest_ip=parts[3],
                dest_port=safe_int(parts[4]),
                dest_hostname=parts[5],
                protocol=parts[6],
                process_name=parts[7],
                process_path=parts[8] if len(parts) > 8 else "",
                process_id=safe_int(parts[9]) if len(parts) > 9 else 0,
                user=parts[10] if len(parts) > 10 else "",
            )
        except Exception:
            return None

    @staticmethod
    def get_field(event: dict, field_name: str) -> str:
        return event.get(field_name, "")
