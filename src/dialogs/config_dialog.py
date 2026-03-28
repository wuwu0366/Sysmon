from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QDoubleSpinBox
)
from PyQt5.QtCore import Qt

from src.utils.config_manager import ConfigManager


class ConfigDialog(QDialog):
    def __init__(self, config: ConfigManager):
        super().__init__()
        self._config = config
        self._init_ui()

    def _init_ui(self):
        self.setWindowTitle("配置")
        self.setMinimumWidth(400)

        layout = QVBoxLayout()

        blacklist_layout = QHBoxLayout()
        blacklist_layout.addWidget(QLabel("黑名单路径:"))
        self._blacklist_path = QLineEdit()
        self._blacklist_path.setText(self._config.get_blacklist_path())
        blacklist_layout.addWidget(self._blacklist_path)
        layout.addLayout(blacklist_layout)

        poll_layout = QHBoxLayout()
        poll_layout.addWidget(QLabel("轮询间隔 (秒):"))
        self._poll_interval = QDoubleSpinBox()
        self._poll_interval.setRange(0.5, 10.0)
        self._poll_interval.setSingleStep(0.5)
        self._poll_interval.setValue(self._config.get_poll_interval())
        poll_layout.addWidget(self._poll_interval)
        poll_layout.addStretch()
        layout.addLayout(poll_layout)

        layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._save_btn = QPushButton("保存")
        self._save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(self._save_btn)

        self._cancel_btn = QPushButton("取消")
        self._cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self._cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _on_save(self):
        self._config.set_blacklist_path(self._blacklist_path.text())
        self._config.set_poll_interval(self._poll_interval.value())
        self.accept()
