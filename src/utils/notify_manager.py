import sys
from typing import Optional

try:
    from win10toast import ToastNotifier
    HAS_WIN10TOAST = True
except ImportError:
    HAS_WIN10TOAST = False


class NotifyManager:
    def __init__(self):
        self._use_modern = self._check_win10()
        self._notifier: Optional[object] = None
        
        if self._use_modern and HAS_WIN10TOAST:
            try:
                self._notifier = ToastNotifier()
            except Exception:
                self._notifier = None

    def _check_win10(self) -> bool:
        try:
            import platform
            if platform.platform().startswith('Windows'):
                version = platform.version()
                major = int(platform.version().split('.')[0])
                if major >= 10:
                    return True
            return False
        except Exception:
            return False

    def send(self, title: str, message: str, callback=None):
        if self._use_modern and self._notifier:
            try:
                self._notifier.show_toast(
                    title=title,
                    msg=message,
                    duration=5,
                    threaded=True,
                    callback_on_click=callback
                )
                return
            except Exception:
                pass
        
        self._fallback_notify(title, message)

    def _fallback_notify(self, title: str, message: str):
        try:
            from ctypes import windll
            import ctypes.wintypes as wintypes
            
            class NOTIFYICONDATA(ctypes.Structure):
                _fields_ = [
                    ('cbSize', wintypes.DWORD),
                    ('hWnd', wintypes.HWND),
                    ('uID', wintypes.UINT),
                    ('uFlags', wintypes.UINT),
                    ('uCallbackMessage', wintypes.UINT),
                    ('hIcon', wintypes.HICON),
                    ('szTip', wintypes.WCHAR * 128),
                    ('dwState', wintypes.DWORD),
                    ('dwStateMask', wintypes.DWORD),
                    ('szInfo', wintypes.WCHAR * 256),
                    ('uTimeout', wintypes.UINT),
                    ('szInfoTitle', wintypes.WCHAR * 64),
                    ('dwInfoFlags', wintypes.DWORD),
                ]

            NIF_INFO = 0x00000010
            
            nid = NOTIFYICONDATA()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
            nid.uFlags = NIF_INFO
            nid.szInfoTitle = title
            nid.szInfo = message
            
            shell32 = windll.shell32
            shell32.Shell_NotifyIconW(0x00000001, ctypes.byref(nid))
        except Exception:
            pass
