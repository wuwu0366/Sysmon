from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextBrowser
from PyQt5.QtCore import Qt


class SysmonNotFoundDialog(QDialog):
    def __init__(self):
        super().__init__()
        self._should_continue = False
        self._init_ui()

    def _init_ui(self):
        self.setWindowTitle("Sysmon 未安装")
        self.setMinimumWidth(500)
        self.setMinimumHeight(300)

        layout = QVBoxLayout()

        title_label = QLabel("检测到 Sysmon 未安装")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title_label)

        info_label = QLabel(
            "Sysmon (System Monitor) 是 Windows 系统监控工具，用于记录系统事件。\n\n"
            "本工具需要 Sysmon 运行才能监控网络连接事件。"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        self._browser = QTextBrowser()
        self._browser.setHtml("""
        <h3>安装步骤：</h3>
        <ol>
            <li>下载 SysinternalsSuite: 
                <a href='https://download.sysinternals.com/files/SysinternalsSuite.zip'>
                https://download.sysinternals.com/files/SysinternalsSuite.zip
                </a>
            </li>
            <li>解压到任意目录（如 C:\Sysinternals）</li>
            <li>以管理员身份打开命令提示符</li>
            <li>运行以下命令安装 Sysmon:<br>
                <code>sysmon -accepteula -i</code>
            </li>
            <li>可选：配置 Sysmon 监控网络事件（EventID 3）<br>
                <code>sysmon -c</code>
            </li>
        </ol>
        """)
        layout.addWidget(self._browser)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self._continue_btn = QPushButton("继续运行（可能无法监控）")
        self._continue_btn.clicked.connect(self._on_continue)
        btn_layout.addWidget(self._continue_btn)

        self._exit_btn = QPushButton("退出")
        self._exit_btn.clicked.connect(self._on_exit)
        btn_layout.addWidget(self._exit_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _on_continue(self):
        self._should_continue = True
        self.accept()

    def _on_exit(self):
        self._should_continue = False
        self.reject()

    def should_continue(self) -> bool:
        return self._should_continue
