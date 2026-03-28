# Implementation Task List

Feature: sysmon-log-monitor
Created: 2026-03-27

## Phases

### Phase 1: Project Setup

- [ ] 创建项目目录结构
- [ ] 创建 `requirements.txt` 依赖清单
- [ ] 创建 `main.py` 程序入口
- [ ] 创建 `manifest.xml` Windows 清单
- [ ] 创建 `build.spec` PyInstaller 配置
- [ ] 验证 Python 3.8 + PyQt5 开发环境

### Phase 2: Data Models

- [ ] 创建 `src/models/event.py` - SysmonEvent 数据类
- [ ] 创建 `src/models/blacklist.py` - BlacklistEntry 数据类
- [ ] 创建 `src/models/__init__.py`

### Phase 3: Core Parsing

- [ ] 创建 `src/parsers/sysmon_parser.py` - SysmonParser 事件解析器
- [ ] 创建 `src/parsers/__init__.py`
- [ ] 实现 parse_event() XML 解析
- [ ] 实现 parse_csv_line() CSV 解析
- [ ] 单元测试: SysmonParser

### Phase 4: Blacklist Matching

- [ ] 创建 `src/matchers/blacklist_matcher.py` - BlacklistMatcher
- [ ] 创建 `src/matchers/__init__.py`
- [ ] 实现 load_from_file() 文件加载
- [ ] 实现 add_entry() / remove_entry() 条目管理
- [ ] 实现 match() 匹配逻辑
- [ ] 单元测试: BlacklistMatcher

### Phase 5: Event Cache

- [ ] 创建 `src/cache/event_cache.py` - EventCache
- [ ] 创建 `src/cache/__init__.py`
- [ ] 实现 add() 添加事件
- [ ] 实现 get_all() / filter() 查询
- [ ] 实现 clear() 清空
- [ ] 单元测试: EventCache

### Phase 6: Event Monitor (Real-time)

- [ ] 创建 `src/monitors/event_monitor.py` - EventMonitor QThread
- [ ] 创建 `src/monitors/__init__.py`
- [ ] 实现 start_monitoring() / stop_monitoring()
- [ ] 实现 pause_monitoring() / resume_monitoring()
- [ ] 实现信号: signal_new_event, signal_error, signal_stats
- [ ] 集成 pywin32 Windows 事件日志读取

### Phase 7: Utilities

- [ ] 创建 `src/utils/config_manager.py` - ConfigManager 配置管理
- [ ] 创建 `src/utils/notify_manager.py` - NotifyManager 通知管理 (Win7兼容)
- [ ] 创建 `src/utils/report_exporter.py` - ReportExporter 导出功能
- [ ] 创建 `src/utils/__init__.py`

### Phase 8: UI - Dialogs

- [ ] 创建 `src/dialogs/__init__.py`
- [ ] 创建 `src/dialogs/sysmon_not_found_dialog.py` - Sysmon 未安装对话框
- [ ] 创建 `src/dialogs/blacklist_dialog.py` - 黑名单管理对话框
- [ ] 创建 `src/dialogs/config_dialog.py` - 配置对话框

### Phase 9: UI - Main Window

- [ ] 创建 `src/main_window.py` - MainWindow 主窗口
- [ ] 实现窗口布局 (标题栏、工具栏、搜索栏、状态栏、表格、底部栏)
- [ ] 实现表格列定义和显示
- [ ] 实现事件列表更新和行高亮
- [ ] 实现搜索和筛选功能
- [ ] 集成 EventMonitor 信号槽
- [ ] 实现暂停/停止控制

### Phase 10: System Tray

- [ ] 实现系统托盘图标
- [ ] 实现托盘上下文菜单
- [ ] 实现双击恢复窗口
- [ ] 实现最小化到托盘

### Phase 11: Integration & Testing

- [ ] 集成测试: 正常启动流程
- [ ] 集成测试: CSV 导入
- [ ] 集成测试: 告警触发和通知
- [ ] 集成测试: 导出功能
- [ ] 修复发现的 bug

### Phase 12: Build & Release

- [ ] 创建 assets/icon.ico 应用图标
- [ ] 运行 PyInstaller 打包
- [ ] 测试生成的 exe 文件
- [ ] 创建 README.md 用户文档

## Task Dependencies

```
Phase 1 (Setup)
    │
    ├──► Phase 2 (Models) ──► Phase 3 (Parser) ──► Phase 4 (Matcher)
    │                                                   │
    ▼                                                   ▼
Phase 5 (Cache) ◄───────────────────────────────────────┘
    │
    ▼
Phase 6 (Monitor) ──► Phase 7 (Utils) ──► Phase 8 (Dialogs)
                                                    │
                                                    ▼
                                            Phase 9 (MainWindow)
                                                    │
                                                    ▼
                                            Phase 10 (System Tray)
                                                    │
                                                    ▼
                                            Phase 11 (Integration)
                                                    │
                                                    ▼
                                            Phase 12 (Build & Release)
```

## Priority Order

1. Phase 1-6: 核心功能 (程序能运行、解析、匹配)
2. Phase 7-8: 配置和对话框
3. Phase 9: 主界面
4. Phase 10: 系统托盘
5. Phase 11-12: 测试和打包
