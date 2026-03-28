import time
from datetime import datetime
from typing import List, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QToolBar, QAction, QStatusBar, QLabel, QLineEdit, QCheckBox,
    QPushButton, QFileDialog, QMessageBox, QSystemTrayIcon, QMenu,
    QScrollBar, QStyle, QStyledItemDelegate, QStyleOptionViewItem
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot, QRect, QModelIndex
from PyQt5.QtGui import QIcon, QColor, QPalette

from src.monitors.event_monitor import EventMonitor
from src.matchers.blacklist_matcher import BlacklistMatcher
from src.cache.event_cache import EventCache
from src.parsers.sysmon_parser import SysmonParser
from src.utils.config_manager import ConfigManager
from src.utils.notify_manager import NotifyManager
from src.utils.report_exporter import ReportExporter
from src.dialogs.blacklist_dialog import BlacklistDialog
from src.dialogs.config_dialog import ConfigDialog
from src.models.event import SysmonEvent, DisplayEvent


class EventDetailDelegate(QStyledItemDelegate):
    EXPANDED_HEIGHT = 120
    COLLAPSED_HEIGHT = 30

    def sizeHint(self, option: QStyleOptionViewItem, index):
        return QRect(0, 0, option.rect.width(), self.COLLAPSED_HEIGHT)


class VirtualEventTable(QTableWidget):
    ROW_HEIGHT = 30
    VISIBLE_ROWS = 50
    MAX_TOTAL_ROWS = 100000

    def __init__(self):
        super().__init__()
        self._visible_start = 0
        self._visible_end = self.VISIBLE_ROWS
        self._scroll_offset = 0
        self._expanded_rows = set()
        self._verticalScrollBar().valueChanged.connect(self._on_scroll)

    def _on_scroll(self, value):
        max_val = self._verticalScrollBar().maximum()
        if max_val > 0:
            self._scroll_offset = value / max_val

    def setRowCount(self, rows: int):
        super().setRowCount(min(rows, self.MAX_TOTAL_ROWS))

    def update_visible_rows(self, start: int, end: int):
        self._visible_start = start
        self._visible_end = end


class MainWindow(QMainWindow):
    COLUMNS = [
        ("时间", 80),
        ("源IP", 110),
        ("目的IP", 110),
        ("目的域名", 150),
        ("端口", 50),
        ("协议", 50),
        ("进程名", 100),
        ("PID", 50),
        ("判定", 60),
    ]

    def __init__(self, config: ConfigManager):
        super().__init__()
        self._config = config
        self._monitoring = False
        self._start_time: Optional[datetime] = None
        self._cache = EventCache()
        self._matcher = BlacklistMatcher()
        self._notify_manager = NotifyManager()
        self._monitor: Optional[EventMonitor] = None
        self._batch_timer = QTimer()
        self._batch_timer.timeout.connect(self._flush_batch)
        self._batch_buffer: List[SysmonEvent] = []
        self._display_buffer: List[DisplayEvent] = []
        self._expanded_rows = set()
        self._filter_alerts_only = False
        self._exact_match = False
        self._search_query = ""
        self._alerts_only = False

        self._init_ui()
        self._init_monitor()
        self._load_blacklist()

    def _init_ui(self):
        self.setWindowTitle("Sysmon 日志可视化监控")
        geometry = self._config.get_window_geometry()
        self.resize(geometry[0], geometry[1])

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        config_action = QAction("配置", self)
        config_action.triggered.connect(self._on_config)
        toolbar.addAction(config_action)

        tray_action = QAction("最小化到托盘", self)
        tray_action.triggered.connect(self._on_minimize_to_tray)
        toolbar.addAction(tray_action)

        search_layout = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("搜索...")
        self._search_input.textChanged.connect(self._on_search_changed)
        search_layout.addWidget(self._search_input)

        self._exact_checkbox = QCheckBox("精确匹配")
        self._exact_checkbox.stateChanged.connect(self._on_filter_changed)
        search_layout.addWidget(self._exact_checkbox)

        self._alerts_checkbox = QCheckBox("仅显示告警")
        self._alerts_checkbox.stateChanged.connect(self._on_filter_changed)
        search_layout.addWidget(self._alerts_checkbox)

        layout.addLayout(search_layout)

        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        for i, (_, width) in enumerate(self.COLUMNS):
            self._table.setColumnWidth(i, width)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.itemClicked.connect(self._on_row_clicked)
        layout.addWidget(self._table)

        status_layout = QHBoxLayout()
        self._status_label = QLabel("未监控")
        status_layout.addWidget(self._status_label)

        self._alert_label = QLabel("告警: 0")
        status_layout.addWidget(self._alert_label)

        self._total_label = QLabel("总事件: 0")
        status_layout.addWidget(self._total_label)

        self._time_label = QLabel("00:00:00")
        status_layout.addWidget(self._time_label)

        status_layout.addStretch()

        self._pause_btn = QPushButton("暂停")
        self._pause_btn.clicked.connect(self._on_pause)
        self._pause_btn.setEnabled(False)
        status_layout.addWidget(self._pause_btn)

        self._stop_btn = QPushButton("停止")
        self._stop_btn.clicked.connect(self._on_stop)
        self._stop_btn.setEnabled(False)
        status_layout.addWidget(self._stop_btn)

        layout.addLayout(status_layout)

        footer_layout = QHBoxLayout()
        self._blacklist_btn = QPushButton("黑名单管理")
        self._blacklist_btn.clicked.connect(self._on_blacklist)
        footer_layout.addWidget(self._blacklist_btn)

        self._add_to_blacklist_btn = QPushButton("添加当前到黑名单")
        self._add_to_blacklist_btn.clicked.connect(self._on_add_to_blacklist)
        footer_layout.addWidget(self._add_to_blacklist_btn)

        self._export_csv_btn = QPushButton("导出CSV")
        self._export_csv_btn.clicked.connect(self._on_export_csv)
        footer_layout.addWidget(self._export_csv_btn)

        self._export_json_btn = QPushButton("导出JSON")
        self._export_json_btn.clicked.connect(self._on_export_json)
        footer_layout.addWidget(self._export_json_btn)

        self._clear_btn = QPushButton("清空列表")
        self._clear_btn.clicked.connect(self._on_clear)
        footer_layout.addWidget(self._clear_btn)

        footer_layout.addStretch()

        self._start_btn = QPushButton("开始监控")
        self._start_btn.clicked.connect(self._on_start)
        footer_layout.addWidget(self._start_btn)

        layout.addLayout(footer_layout)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)

        self._timer = QTimer()
        self._timer.timeout.connect(self._update_time)
        self._batch_timer.start(100)

        self._setup_tray()

    def _setup_tray(self):
        self._tray = QSystemTrayIcon(self)
        self._tray.setToolTip("Sysmon Log Monitor")

        menu = QMenu()
        open_action = menu.addAction("打开")
        open_action.triggered.connect(self._show)
        
        quit_action = menu.addAction("退出")
        quit_action.triggered.connect(self.close)

        self._tray.setContextMenu(menu)
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.hide()

    def _init_monitor(self):
        self._monitor = EventMonitor()
        self._monitor.set_matcher(self._matcher)
        self._monitor.set_cache(self._cache)
        self._monitor.set_notify_callback(self._on_malicious_event)
        self._monitor.signal_new_event.connect(self._on_new_event)
        self._monitor.signal_stats.connect(self._on_stats_update)

    def _load_blacklist(self):
        blacklist_path = self._config.get_blacklist_path()
        self._matcher.load_from_file(blacklist_path)

    @pyqtSlot()
    def _on_start(self):
        if not self._monitoring:
            self._monitoring = True
            self._start_time = datetime.now()
            self._timer.start(1000)
            self._monitor.start_monitoring()
            self._status_label.setText("监控中")
            self._start_btn.setEnabled(False)
            self._pause_btn.setEnabled(True)
            self._stop_btn.setEnabled(True)

    @pyqtSlot()
    def _on_pause(self):
        if self._monitor:
            try:
                if self._pause_btn.text() == "暂停":
                    self._monitor.pause_monitoring()
                    self._pause_btn.setText("继续")
                    self._status_label.setText("已暂停")
                else:
                    self._monitor.resume_monitoring()
                    self._pause_btn.setText("暂停")
                    self._status_label.setText("监控中")
            except Exception as e:
                print(f"Pause error: {e}")

    @pyqtSlot()
    def _on_stop(self):
        if self._monitor:
            try:
                self._monitor.stop_monitoring()
            except Exception as e:
                print(f"Stop error: {e}")
        self._monitoring = False
        self._timer.stop()
        self._status_label.setText("未监控")
        self._start_btn.setEnabled(True)
        self._pause_btn.setEnabled(False)
        self._pause_btn.setText("暂停")
        self._stop_btn.setEnabled(False)

    @pyqtSlot(SysmonEvent)
    def _on_new_event(self, event: SysmonEvent):
        self._batch_buffer.append(event)

    @pyqtSlot(int, int)
    def _on_stats_update(self, total: int, malicious: int):
        self._total_label.setText(f"总事件: {total}")
        self._alert_label.setText(f"告警: {malicious}")

    def _flush_batch(self):
        if not self._batch_buffer:
            return

        self._display_buffer.extend([
            DisplayEvent(e, False, e.is_malicious) 
            for e in self._batch_buffer
        ])
        self._batch_buffer.clear()

        malicious = [d for d in self._display_buffer if d.is_malicious]
        normal = [d for d in self._display_buffer if not d.is_malicious]
        display_list = malicious + normal

        self._update_table(display_list)

    def _update_table(self, events: List[DisplayEvent]):
        filtered = events
        if self._alerts_only:
            filtered = [e for e in filtered if e.is_malicious]

        if self._search_query:
            query = self._search_query.lower()
            filtered = [
                e for e in filtered
                if (query in e.event.source_ip.lower() or
                    query in e.event.dest_ip.lower() or
                    query in e.event.dest_hostname.lower() or
                    query in e.event.process_name.lower())
            ]

        self._table.setRowCount(len(filtered))
        for row, de in enumerate(filtered):
            event = de.event
            self._table.setItem(row, 0, QTableWidgetItem(
                event.timestamp.strftime("%H:%M:%S") if event.timestamp else ""))
            self._table.setItem(row, 1, QTableWidgetItem(event.source_ip))
            self._table.setItem(row, 2, QTableWidgetItem(event.dest_ip))
            self._table.setItem(row, 3, QTableWidgetItem(event.dest_hostname))
            self._table.setItem(row, 4, QTableWidgetItem(str(event.dest_port)))
            self._table.setItem(row, 5, QTableWidgetItem(event.protocol))
            self._table.setItem(row, 6, QTableWidgetItem(event.process_name))
            self._table.setItem(row, 7, QTableWidgetItem(str(event.process_id)))
            self._table.setItem(row, 8, QTableWidgetItem(
                "恶意" if event.is_malicious else "正常"))

            if event.is_malicious:
                for col in range(len(self.COLUMNS)):
                    item = self._table.item(row, col)
                    if item:
                        item.setBackground(QColor(255, 100, 100))

    def _update_time(self):
        if self._start_time:
            elapsed = datetime.now() - self._start_time
            hours = elapsed.seconds // 3600
            minutes = (elapsed.seconds % 3600) // 60
            seconds = elapsed.seconds % 60
            self._time_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _on_malicious_event(self, event: SysmonEvent):
        pass

    @pyqtSlot()
    def _on_config(self):
        dialog = ConfigDialog(self._config)
        if dialog.exec_():
            self._load_blacklist()

    @pyqtSlot()
    def _on_blacklist(self):
        dialog = BlacklistDialog(self._matcher)
        dialog.exec_()

    @pyqtSlot()
    def _on_add_to_blacklist(self):
        current_row = self._table.currentRow()
        if current_row < 0:
            return

        dest_ip = self._table.item(current_row, 2).text()
        if dest_ip:
            self._matcher.add_entry(dest_ip)
            QMessageBox.information(self, "已添加", f"{dest_ip} 已添加到黑名单")

    @pyqtSlot()
    def _on_export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出CSV", "", "CSV Files (*.csv)")
        if path:
            events = [d.event for d in self._display_buffer]
            if ReportExporter.export_csv(events, path):
                QMessageBox.information(self, "导出成功", f"已保存到 {path}")
            else:
                QMessageBox.warning(self, "导出失败", "无法保存文件")

    @pyqtSlot()
    def _on_export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出JSON", "", "JSON Files (*.json)")
        if path:
            events = [d.event for d in self._display_buffer]
            if ReportExporter.export_json(events, path):
                QMessageBox.information(self, "导出成功", f"已保存到 {path}")
            else:
                QMessageBox.warning(self, "导出失败", "无法保存文件")

    @pyqtSlot()
    def _on_clear(self):
        self._cache.clear()
        self._display_buffer.clear()
        self._table.setRowCount(0)
        self._total_label.setText("总事件: 0")
        self._alert_label.setText("告警: 0")

    @pyqtSlot(str)
    def _on_search_changed(self, text: str):
        self._search_query = text
        self._flush_batch()

    @pyqtSlot(int)
    def _on_filter_changed(self, state):
        self._exact_match = self._exact_checkbox.isChecked()
        self._alerts_only = self._alerts_checkbox.isChecked()
        self._flush_batch()

    @pyqtSlot(QTableWidgetItem)
    def _on_row_clicked(self, item: QTableWidgetItem):
        row = item.row()

    def _on_minimize_to_tray(self):
        self.hide()
        self._tray.show()
        self._tray.showMessage("Sysmon Log Monitor", "程序已最小化到托盘")

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self._show()

    def _show(self):
        self.show()
        self.activateWindow()
        self._tray.hide()

    def closeEvent(self, event):
        if self._monitoring:
            self._monitor.stop_monitoring()
        self._config.set_window_geometry(self.width(), self.height())
        event.accept()
