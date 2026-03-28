# Requirements Document

## Introduction

Sysmon Log Visual Monitor (sysmon-log-monitor) 是一款面向 Windows 主机的 Sysmon 日志可视化监控工具，旨在帮助技术能力偏弱的人员快速筛选出与恶意域名/IP 的通讯行为。

## Glossary

- **Sysmon**: Windows Sysinternals 系统监控工具，全称 System Monitor
- **EventID=3**: Sysmon 网络连接事件，表示一次 TCP/UDP 连接
- **黑名单**: 包含恶意域名/IP 的文本文件，每行一个条目
- **evtx**: Windows 事件日志文件格式
- **实时监控**: 程序启动后持续监听 Windows 事件日志通道

## Requirements

### Requirement 1: Sysmon 检测与引导

**User Story:** AS 一个安全分析人员，我需要程序在启动时检测 Sysmon 是否安装，以便在未安装时引导用户正确安装。

#### Acceptance Criteria

1. WHEN 程序启动, THEN 程序 SHALL 检测 `Microsoft-Windows-Sysmon/Operational` 事件通道是否存在
2. IF 事件通道不存在, THEN 程序 SHALL 弹出提示窗口显示 "Sysmon 未安装"
3. IF 事件通道不存在, THEN 程序 SHALL 提供 Sysmon 下载链接和安装说明
4. IF 事件通道存在但程序无权限, THEN 程序 SHALL 提示 "请以管理员权限运行"

---

### Requirement 2: 实时监控 Sysmon 事件日志

**User Story:** AS 一个安全分析人员，我需要程序实时监控本机 Sysmon 日志，以便及时发现可疑网络连接。

#### Acceptance Criteria

1. WHEN 用户点击 "开始监控", THEN 系统 SHALL 每秒查询一次 `Microsoft-Windows-Sysmon/Operational` 通道
2. WHEN 查询到新的 EventID=3 事件, THEN 系统 SHALL 解析并显示以下字段:
   - 时间 (TimeCreated)
   - 源IP (SourceIp)
   - 源端口 (SourcePort)
   - 目的IP (DestinationIp)
   - 目的端口 (DestinationPort)
   - 目的域名 (DestinationHostname)
   - 协议 (Protocol)
   - 进程名 (Image)
   - 进程路径 (ImagePath)
   - PID (ProcessId)
3. WHILE 监控处于活动状态, THEN 系统 SHALL 在界面上实时更新事件列表
4. WHEN 用户点击 "暂停监控", THEN 系统 SHALL 停止查询但保留当前数据
5. WHEN 用户点击 "停止监控", THEN 系统 SHALL 停止查询并清空当前数据

---

### Requirement 3: CSV 日志文件导入

**User Story:** AS 一个安全分析人员，我需要导入 CSV 格式的 Sysmon 日志，以便分析历史数据或多主机日志汇总。

#### Acceptance Criteria

1. WHEN 用户点击 "导入CSV", THEN 系统 SHALL 打开文件选择对话框允许选择多个 CSV 文件
2. WHEN 用户选择CSV文件并确认, THEN 系统 SHALL 解析文件并识别字段映射
3. WHEN 解析成功, THEN 系统 SHALL 将所有事件合并显示在列表中
4. WHEN 解析失败, THEN 系统 SHALL 显示错误提示并跳过该文件

---

### Requirement 4: 本地黑名单匹配

**User Story:** AS 一个安全分析人员，我需要程序根据本地黑名单匹配可疑通讯，以便快速识别恶意行为。

#### Acceptance Criteria

1. WHEN 程序启动, THEN 系统 SHALL 自动加载黑名单文件（如果存在）
2. WHEN 用户点击 "黑名单管理", THEN 系统 SHALL 打开黑名单编辑对话框
3. WHEN 用户添加新条目, THEN 系统 SHALL 验证格式（有效的IP或域名）并追加到黑名单
4. WHEN 用户删除条目, THEN 系统 SHALL 从黑名单中移除该条目
5. WHEN 用户导入黑名单文件, THEN 系统 SHALL 追加新条目到现有黑名单
6. WHEN 匹配到黑名单, THEN 系统 SHALL 高亮该行并标记为 "恶意"

---

### Requirement 5: 搜索与筛选

**User Story:** AS 一个安全分析人员，我需要搜索和筛选功能，以便在大量日志中快速定位目标。

#### Acceptance Criteria

1. WHEN 用户在搜索框输入内容, THEN 系统 SHALL 实时过滤列表显示匹配的条目
2. WHEN 用户勾选 "精确匹配", THEN 系统 SHALL 仅显示完全匹配的条目
3. WHEN 用户勾选 "仅显示告警", THEN 系统 SHALL 仅显示命中黑名单的条目
4. WHEN 用户清空搜索框, THEN 系统 SHALL 显示所有条目

---

### Requirement 6: 可视化界面显示

**User Story:** AS 一个安全分析人员，我需要在界面上清晰显示所有关键字段，以便快速判断通讯情况。

#### Acceptance Criteria

1. WHEN 事件列表有数据, THEN 界面 SHALL 显示以下列: 时间 | 源IP | 目的IP | 目的域名 | 端口 | 协议 | 进程名 | 判定
2. WHEN 条目命中黑名单, THEN 系统 SHALL 以红色背景高亮该行
3. WHEN 条目未命中黑名单, THEN 系统 SHALL 以白色背景显示
4. WHEN 告警数量发生变化, THEN 系统 SHALL 在界面上更新告警计数
5. WHEN 运行时间发生变化, THEN 系统 SHALL 在界面上更新运行时间显示

---

### Requirement 7: 桌面通知

**User Story:** AS 一个安全分析人员，我需要在检测到恶意通讯时收到系统通知，以便在不看界面的情况下也能知晓告警。

#### Acceptance Criteria

1. WHEN 检测到新的恶意通讯, THEN 系统 SHALL 发送 Windows 桌面通知
2. WHEN 通知被点击, THEN 系统 SHALL 将主窗口置于前台
3. IF 通知功能不可用(Win7旧版本), THEN 系统 SHALL 静默失败不影响主功能

---

### Requirement 8: 导出报告

**User Story:** AS 一个安全分析人员，我需要导出告警报告，以便生成安全分析报告。

#### Acceptance Criteria

1. WHEN 用户点击 "导出CSV", THEN 系统 SHALL 将当前告警列表导出为 CSV 文件
2. WHEN 用户点击 "导出JSON", THEN 系统 SHALL 将当前告警列表导出为 JSON 文件
3. WHEN 导出成功, THEN 系统 SHALL 显示保存路径确认

---

### Requirement 9: 系统托盘

**User Story:** AS 一个安全分析人员，我需要最小化到系统托盘，以便在后台持续监控。

#### Acceptance Criteria

1. WHEN 用户点击 "最小化到托盘", THEN 系统 SHALL 隐藏主窗口并在托盘区显示图标
2. WHEN 用户双击托盘图标, THEN 系统 SHALL 恢复主窗口显示
3. WHEN 用户右键托盘图标, THEN 系统 SHALL 显示上下文菜单(打开 | 退出)

---

### Requirement 10: 兼容性要求

**User Story:** AS 一个安全分析人员，我需要在 Windows 7 及以上系统运行本工具，以便覆盖更多客户环境。

#### Acceptance Criteria

1. WHEN 程序在 Windows 7 SP1 上运行, THEN 所有功能 SHALL 正常工作
2. WHEN 程序在 Windows 10/11 上运行, THEN 所有功能 SHALL 正常工作
3. WHEN 程序打包为 exe, THEN 用户 SHALL 可以双击直接运行无需安装 Python 环境

---

## Appendix: Sysmon EventID=3 字段映射

| 事件日志字段 | 显示列名 | 说明 |
|------------|---------|------|
| TimeCreated | 时间 | UTC 时间转换为本地时间 |
| SourceIp | 源IP | 内网 IP |
| SourcePort | 源端口 | 客户端端口 |
| DestinationIp | 目的IP | 外部 IP |
| DestinationPort | 目的端口 | 服务端口 |
| DestinationHostname | 目的域名 | DNS 解析的域名(如有) |
| Protocol | 协议 | TCP/UDP |
| Image | 进程名 | 可执行文件名 |
| ImagePath | 进程路径 | 完整路径 |
| ProcessId | PID | 进程 ID |
| UserName | 用户 | 发起用户 |
