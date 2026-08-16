# 安全策略

## 支持范围

安全修复只保证合入最新版本。部署者应及时升级，并定期检查 GitHub Releases。

## 报告漏洞

请不要公开提交包含漏洞利用细节、生产地址、访问令牌、Cookie、数据库或日志的 Issue。

请通过 GitHub 仓库的 **Security > Report a vulnerability** 私密报告。报告中建议包含受影响版本、复现步骤、影响范围和可行的缓解方式。维护者确认问题后会协调修复与披露时间。

## 部署基线

- 默认保持 `ALLOW_UNSIGNED_TARGETS=false`，只配置可信初始上游。
- 除非上游确实位于内网，否则保持 `ALLOW_PRIVATE_TARGETS=false`。
- 不要提交 `.env`、SQLite 数据库、备份或运行日志。
- 管理面板必须使用 HTTPS，并设置至少 12 字符的独立密码。
- Turnstile 只能作为额外防护，不能替代强密码和及时升级。
- 定期测试备份恢复，并限制 `/opt/refract/.env` 和备份目录权限。
