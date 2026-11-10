# 初版 v1.0.0 验证记录

2026-11-09，本地 Windows 开发环境验证：

- Go `go test ./...` 通过，覆盖默认配置与密码、北京时间 09:00 的边界、登录/退出与会话、跨站写入拒绝、空账号提示、SQLite 快照保留与备注持久化、移除账号隐藏、同步互斥与历史记录。
- IP 解析测试通过：URL 编码及字面加号、Deny/NotIpAddress、Allow/IpAddress、拒绝名单、限定 Action、额外 Condition、IfExists、集合操作符、IPv6、无效或缺失文档，以及权限边界中的 IP 条件。
- Windows 可执行文件已实际执行 `-version`，输出 `audit-server 1.0.0`；`-check-config` 通过；启动后 `/api/health` 返回 200。
- `CGO_ENABLED=0` 的 Linux amd64、arm64 交叉编译通过；未在 Windows 上执行 Linux 二进制。
- 配套 Vue 前端 TypeScript 检查与 Vite 生产构建通过。
- 浏览器验证默认账号登录/退出、空账号状态、手动获取的配置缺失提示、全部 19 字段、策略来源、IP 条件原值和 JSON 展示；未发现 JavaScript 控制台错误。
- `install.sh` 通过 Bash 语法与帮助入口检查，默认监听地址等参数验证通过。当前机器没有运行 Linux/systemd，因此未宣称已执行真实服务器安装。

未配置真实 AWS 凭证，尚未完成真实账号端到端采集。采集逻辑基于 AWS SDK v2 与官方 API 文档；部署并填入凭证后，须点击“立即全部获取”，核对账号状态、用户数、策略、IP 条件及告警。演示数据使用保留测试 IP 和虚构账号 ID，且仅在显式演示入口展示。

## 2026-11-10 安装脚本运行库修复

针对服务器报告的 `node: error while loading shared libraries: libatomic.so.1`：

- Debian/Ubuntu 自动安装 `libatomic1`、`libstdc++6`；dnf/yum 系统自动安装 `libatomic`、`libstdc++`。
- Node 下载校验解压后，在拉取前端和调用 npm 之前运行 `node --version`；失败时保留动态加载器原始诊断并给出补齐运行库的命令。
- 安装脚本 Bash 语法与帮助入口检查通过。
- `bash tests/test_install_runtime.sh` 的 6 项模拟回归通过，覆盖三类包管理器、`--no-deps`、Node 缺库时提前终止、正常 Node 继续安装。测试不执行特权安装或下载。

这次修改只涉及安装脚本、对应回归测试和说明文档；未修改 Go 程序或前端功能。现有配置、数据库与已合并的端口调整保留。尚未在用户服务器上重新执行安装，不将模拟测试等同于 Linux 现场安装成功。
