from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QMessageBox, QLabel, QLineEdit
)
from PyQt5.QtCore import Qt

from src.matchers.blacklist_matcher import BlacklistMatcher
from src.models.blacklist import BlacklistEntry


class BlacklistDialog(QDialog):
    def __init__(self, matcher: BlacklistMatcher):
        super().__init__()
        self._matcher = matcher
        self._init_ui()
        self._load_entries()

    def _init_ui(self):
        self.setWindowTitle("黑名单管理")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        layout = QVBoxLayout()

        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["类型", "条目", "来源"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self._table)

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("新增条目:"))
        self._input = QLineEdit()
        self._input.setPlaceholderText("输入 IP 或域名")
        input_layout.addWidget(self._input)

        self._add_btn = QPushButton("添加")
        self._add_btn.clicked.connect(self._on_add)
        input_layout.addWidget(self._add_btn)

        layout.addLayout(input_layout)

        btn_layout = QHBoxLayout()

        self._import_btn = QPushButton("导入文件")
        self._import_btn.clicked.connect(self._on_import)
        btn_layout.addWidget(self._import_btn)

        self._export_btn = QPushButton("导出文件")
        self._export_btn.clicked.connect(self._on_export)
        btn_layout.addWidget(self._export_btn)

        self._delete_btn = QPushButton("删除选中")
        self._delete_btn.clicked.connect(self._on_delete)
        btn_layout.addWidget(self._delete_btn)

        btn_layout.addStretch()

        self._close_btn = QPushButton("关闭")
        self._close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self._close_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _load_entries(self):
        self._table.setRowCount(0)
        entries = self._matcher.get_all_entries()
        for row, (value, entry_type) in enumerate(entries):
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(entry_type))
            self._table.setItem(row, 1, QTableWidgetItem(value))
            self._table.setItem(row, 2, QTableWidgetItem("manual"))

    def _on_add(self):
        value = self._input.text().strip()
        if not value:
            return

        if not BlacklistEntry.validate(value):
            QMessageBox.warning(self, "格式错误", "请输入有效的 IP 地址或域名")
            return

        if self._matcher.add_entry(value):
            self._input.clear()
            self._load_entries()
        else:
            QMessageBox.warning(self, "添加失败", "无法添加该条目")

    def _on_delete(self):
        selected = self._table.selectedIndexes()
        if not selected:
            return

        row = selected[0].row()
        value_item = self._table.item(row, 1)
        if value_item:
            value = value_item.text()
            self._matcher.remove_entry(value)
            self._load_entries()

    def _on_import(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择黑名单文件", "", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            if self._matcher.load_from_file(path):
                self._load_entries()
                QMessageBox.information(self, "导入成功", "黑名单已更新")
            else:
                QMessageBox.warning(self, "导入失败", "无法读取文件")

    def _on_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存黑名单文件", "blacklist.txt", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            if self._matcher.save_to_file(path):
                QMessageBox.information(self, "导出成功", "黑名单已保存")
            else:
                QMessageBox.warning(self, "导出失败", "无法保存文件")
