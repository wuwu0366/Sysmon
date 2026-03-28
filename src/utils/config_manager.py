import os
from configparser import ConfigParser


class ConfigManager:
    CONFIG_FILE = "config.ini"

    def __init__(self):
        self._config = ConfigParser()
        self._load()

    def _load(self):
        if os.path.exists(self.CONFIG_FILE):
            self._config.read(self.CONFIG_FILE, encoding='utf-8')
        else:
            self._config['DEFAULT'] = {
                'blacklist_path': 'blacklist.txt',
                'window_width': '1200',
                'window_height': '800',
                'poll_interval': '1',
            }
            self._save()

    def _save(self):
        with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
            self._config.write(f)

    def get_blacklist_path(self) -> str:
        return self._config.get('DEFAULT', 'blacklist_path', fallback='blacklist.txt')

    def set_blacklist_path(self, path: str):
        self._config['DEFAULT']['blacklist_path'] = path
        self._save()

    def get_window_geometry(self) -> tuple:
        width = self._config.getint('DEFAULT', 'window_width', fallback=1200)
        height = self._config.getint('DEFAULT', 'window_height', fallback=800)
        return (width, height)

    def set_window_geometry(self, width: int, height: int):
        self._config['DEFAULT']['window_width'] = str(width)
        self._config['DEFAULT']['window_height'] = str(height)
        self._save()

    def get_poll_interval(self) -> float:
        return self._config.getfloat('DEFAULT', 'poll_interval', fallback=1.0)

    def set_poll_interval(self, interval: float):
        self._config['DEFAULT']['poll_interval'] = str(interval)
        self._save()

    def save(self):
        self._save()
