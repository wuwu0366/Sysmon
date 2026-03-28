from typing import Optional
from src.models.event import SysmonEvent, MatchResult
from src.models.blacklist import BlacklistEntry


class BlacklistMatcher:
    def __init__(self):
        self._ip_set = set()
        self._domain_set = set()
        self._loaded = False

    def load_from_file(self, filepath: str) -> bool:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = BlacklistEntry.parse(line)
                    if entry:
                        self._add_entry_internal(entry)
            self._loaded = True
            return True
        except FileNotFoundError:
            self._loaded = True
            return True
        except Exception:
            return False

    def _add_entry_internal(self, entry: BlacklistEntry):
        if entry.entry_type == "ip":
            self._ip_set.add(entry.value.lower())
        elif entry.entry_type == "domain":
            self._domain_set.add(entry.value.lower())

    def add_entry(self, entry: str) -> bool:
        if not BlacklistEntry.validate(entry):
            return False
        entry_type = BlacklistEntry.guess_type(entry)
        if entry_type == "ip":
            self._ip_set.add(entry.lower())
        elif entry_type == "domain":
            self._domain_set.add(entry.lower())
        return True

    def remove_entry(self, entry: str) -> bool:
        entry_lower = entry.lower()
        if entry_lower in self._ip_set:
            self._ip_set.discard(entry_lower)
            return True
        if entry_lower in self._domain_set:
            self._domain_set.discard(entry_lower)
            return True
        return False

    def save_to_file(self, filepath: str) -> bool:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for ip in sorted(self._ip_set):
                    f.write(f"{ip}|ip|manual|\n")
                for domain in sorted(self._domain_set):
                    f.write(f"{domain}|domain|manual|\n")
            return True
        except Exception:
            return False

    def match(self, event: SysmonEvent) -> MatchResult:
        result = MatchResult()

        if event.dest_ip and event.dest_ip.lower() in self._ip_set:
            result.ip_matched = True
            result.is_malicious = True
            result.matched_entry = event.dest_ip

        if event.dest_hostname:
            hostname_lower = event.dest_hostname.lower()
            if hostname_lower in self._domain_set:
                result.domain_matched = True
                result.is_malicious = True
                result.matched_entry = event.dest_hostname
            else:
                for domain in self._domain_set:
                    if hostname_lower.endswith(domain) or domain in hostname_lower:
                        result.domain_matched = True
                        result.is_malicious = True
                        result.matched_entry = domain
                        break

        return result

    def get_all_entries(self) -> list:
        entries = []
        for ip in sorted(self._ip_set):
            entries.append((ip, "ip"))
        for domain in sorted(self._domain_set):
            entries.append((domain, "domain"))
        return entries

    def is_loaded(self) -> bool:
        return self._loaded
