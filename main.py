#!/usr/bin/env python3
import sys
import os

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

from src.main_window import MainWindow
from src.dialogs.sysmon_not_found_dialog import SysmonNotFoundDialog
from src.utils.notify_manager import NotifyManager
from src.utils.config_manager import ConfigManager


def check_sysmon_installed() -> bool:
    try:
        import win32evtlog
        channel = "Microsoft-Windows-Sysmon/Operational"
        handle = win32evtlog.OpenEventLog(None, channel)
        if handle:
            win32evtlog.CloseEventLog(handle)
            return True
        return False
    except Exception:
        return False


def check_admin权限() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setApplicationName("Sysmon Log Monitor")
    app.setOrganizationName("Security Tools")
    
    if not check_sysmon_installed():
        dialog = SysmonNotFoundDialog()
        dialog.exec_()
        if not dialog.should_continue():
            return 1
    
    if not check_admin权限():
        from PyQt5.QtWidgets import QMessageBox
        QMessageBox.warning(
            None,
            "权限不足",
            "请右键选择「以管理员身份运行」"
        )
        return 1
    
    config = ConfigManager()
    window = MainWindow(config)
    window.show()
    
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
