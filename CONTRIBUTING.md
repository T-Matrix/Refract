# 参与贡献

感谢你改进 Refract。提交改动前，请先搜索现有 Issue，较大的功能建议先创建 Issue 说明使用场景和设计方向。

## 本地开发

需要 Go 1.26.6 或更高兼容版本。

```bash
git clone https://github.com/T-Matrix/Refract.git
cd Refract
go test ./...
go run ./cmd/gateway
```

运行服务至少需要提供 32 字符的 `SIGNING_SECRET`。启用管理面板时还需要 32 字符的 `ADMIN_SESSION_SECRET`，完整参数参见 `.env.example`。

## 提交要求

- 保持改动聚焦，不在同一 PR 中混入无关重构。
- 为行为修改补充测试，提交前运行 `go test ./...` 和 `go vet ./...`。
- 不要提交真实域名、IP、Token、Cookie、数据库、备份或日志。
- 前端改动需同时检查桌面与移动视口，并保持键盘操作和可见焦点。
- 提交信息使用简短祈使句，PR 描述说明动机、行为变化和验证方式。
