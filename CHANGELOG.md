# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的结构，版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [1.9.0] - 2026-08-17

### 新增

- 系统设置新增结构化运行配置，可管理默认上游、允许上游、通用反代、客户端 IP、缓存、重写上限、超时与并发限制。
- 运行配置使用私有文件、原子替换和上一版本备份；配置损坏时启动过程自动回退。
- 原生 systemd 部署新增受限维护 Socket，让低权限面板进程可以请求安装经过官方 Release 与 SHA-256 双重校验的更新。

### 安全

- 入口域名只读展示，避免只修改应用地址而未同步 DNS、证书和前置代理。
- 维护 Socket 不接受命令、URL、服务名或文件路径，Web 服务继续以无特权账号运行。

## [1.7.2] - 2026-08-16

### 改进

- 一键部署脚本支持 Alpine Linux 与 OpenRC 服务启动。
- 已安装 Docker 但缺少 Compose 时，自动下载官方 Compose 插件并校验 SHA-256。
- GitHub Actions 升级到当前 Node.js 24 运行时版本，消除弃用告警。

## [1.7.1] - 2026-08-16

### 新增

- 实时连接管理、按秒上传/下载速率与连接中断。
- 24 小时、7 天、30 天、90 天统计切换与 CSV 导出。
- 全球请求地图，中国大陆精确到省份，其他地区按国家聚合。
- 客户端 IP 并发下行聚合与历史峰值统计。
- 域名黑名单、白名单和关闭三种访问规则模式。
- Telegram 每日报告、配置测试和即时测试消息。
- Cloudflare Turnstile 登录验证、配置自测及服务端 Siteverify。
- 管理审计、SQLite 手动/自动备份和安全恢复。
- 首次安装管理员设置页面。

### 修复

- 修复客户端中断流式响应后流量未落库，导致概览及后端统计刷新回弹的问题。
- 修复概览时间范围切换、主要后端流量和实时下行刷新不一致的问题。

[1.7.2]: https://github.com/T-Matrix/Refract/releases/tag/v1.7.2
[1.7.1]: https://github.com/T-Matrix/Refract/releases/tag/v1.7.1
[1.9.0]: https://github.com/T-Matrix/Refract/releases/tag/v1.9.0
