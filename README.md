# AWS 账号审计平台 · Server

Go + SQLite 后端，配套 [Vue 前端](https://github.com/userreksai/AuditPlatform_web)。以 **AWS 账号 → IAM 用户 → 直接/组继承策略 → IP 条件** 展示权限证据。SQLite 不需要独立数据库服务。

## Linux 一键安装

支持运行 systemd 的 Debian/Ubuntu、Rocky/Alma/RHEL/Fedora，amd64 或 arm64，需要联网下载依赖。安装脚本会安装基础工具，从官方站点下载并验证 Go/Node 的 SHA256，构建两端、执行 Go 测试并安装服务。

Node.js 的 Linux 运行依赖也由脚本安装：Debian/Ubuntu 使用 `libatomic1`、`libstdc++6`，dnf/yum 系统使用 `libatomic`、`libstdc++`。下载后先执行 `node --version`，验证成功才继续拉取和构建前端。使用 `--no-deps` 时需自行准备这些运行库。

```bash
git clone https://github.com/userreksai/AuditPlatform_server.git
cd AuditPlatform_server
sudo bash install.sh
```

未找到相邻的 `AuditPlatform_web` 时自动克隆前端仓库。也可指定现有前端源码：

```bash
sudo bash install.sh --web-source /path/to/AuditPlatform_web --listen 0.0.0.0:10001
```

浏览器访问 `http://服务器IP:10001`。默认账号 **auditroot**，默认密码 **a181818.**（末尾英文句号属于密码）。首次安装使用空账号列表，界面正常显示待配置状态，不会生成假 AWS 数据。

安装位置：程序和前端 `/opt/aws-audit/current`；配置 `/etc/aws-audit/config.yaml`；数据库 `/var/lib/aws-audit/audit.db`。配置由 root 持有，服务组只读；数据库由专用 `aws-audit` 用户读写。更新前先构建、测试，再切换程序版本；保留已有配置和数据库，服务启动失败时尝试恢复上个程序版本。`--no-start` 仅安装并启用服务，`--no-deps` 跳过系统依赖安装。已有配置的监听地址不会被 `--listen` 覆盖。

```bash
sudo systemctl status aws-audit
sudo journalctl -u aws-audit -f
sudo systemctl restart aws-audit
```

如需 HTTPS，参考 [Nginx 配置](deploy/nginx.conf.example)，将 Go 监听改为 `127.0.0.1:10001`，配置 `server.secure_cookie: true`。

## 配置账号和登录信息

编辑 `/etc/aws-audit/config.yaml`，然后重启服务。完整参数见 [config.example.yaml](config.example.yaml)。开发时复制为 `config.yaml`；真实配置已加入 Git 忽略列表，禁止将密钥写进示例文件。

```yaml
server:
  address: "0.0.0.0:10001"
  web_directory: "/opt/aws-audit/current/web"
  secure_cookie: false
  session_hours: 12
database:
  path: "/var/lib/aws-audit/audit.db"
auth:
  username: "auditroot"
  password: ""
  # password_hash: "$2a$..." # 可选 bcrypt；填写时优先使用 hash
sync:
  time: "09:00"
  timezone: "Asia/Shanghai"
  timeout_minutes: 30
accounts:
  - id: "production" # 本地稳定标识；后续调整名称/密钥时保留此标识
    name: "生产账号"
    owner: "运维组"
    region: "us-east-1"
    expected_account_id: "123456789012" # 必须替换为实际账号；校验密钥归属
    access_key_id: "REPLACE_ME"
    secret_access_key: "REPLACE_ME"
    session_token: "" # 临时凭证可填写；到期后需要更新配置
    rds_regions: [] # 可选：留空自动采集全部已启用区域；填写如 ["ap-southeast-1"] 则只采集指定区域
  - id: "another-account"
    name: "另一个账号"
    region: "us-east-1"
    access_key_id: "REPLACE_ME"
    secret_access_key: "REPLACE_ME"
```

AWS 中国区使用相应区域，如 `cn-north-1`。相对数据库和前端路径以配置文件所在目录为基准。修改登录账号/密码后重启生效，已有内存会话失效。API 不向前端返回 Secret Access Key、采集密钥或登录密码。

## 采集与字段

默认每天**北京时间 09:00**同步，与服务器本机时区无关。页面“全部获取”启动一次异步全账号采集，可查看执行状态和历史；重复点击不会并发启动。首次部署后配置 AWS Key，点击一次“全部获取”即可建立首份快照。服务器停机期间不补跑历史时间点，恢复后按下一个计划时间执行，也可手动获取。

截图的 19 项字段均有对应展示：账号 ID、账号名称、用户名、负责人、需求检查、用户直接权限、所属用户组、控制台登录权限、是否启用 MFA、Access Key ID、Key 状态、IP 限制策略、IP 白名单限制、IP 判断说明、IP/CIDR 白名单范围、用户组继承权限、创建时间、密码最后使用时间、用户 ID。负责人默认来自账号配置，用户详情内可单独维护负责人、需求检查和备注；这些业务字段不是 AWS 自动生成的结论。

直接和组继承的内联/托管策略均采集，托管策略读取当前默认版本。用户详情保留原始 JSON、策略名、来源组、Sid、Effect、条件操作符和 CIDR。权限边界单独显示，不当作权限授予策略。root 不是 IAM 用户，不混入用户表。

例如 `sp7969` 中 `Deny + NotIpAddress + aws:SourceIp` 表示在该语句覆盖的范围及其他条件下，范围外请求会被显式拒绝；`Allow + IpAddress` 只约束该 Allow 语句；`Deny + IpAddress` 是拒绝名单。界面保留这些差异，抽取的 IP/CIDR 不能统一解释为最终有效白名单。

账号身份/策略列表等关键采集失败时保留上次完整快照并显示错误。部分字段读取失败会标出未知/部分成功及原因，不把失败当作“没有权限”或“MFA 未开启”。账号清单只展示当前配置中的账号。审计备注独立保存，同步不会覆盖。

## AWS API 权限

给每个采集身份附加 [deploy/iam-read-policy.json](deploy/iam-read-policy.json) 中的动作权限即可，不需要 AdministratorAccess。采集过程不修改 IAM 用户、密钥、组或策略；`GenerateCredentialReport` 负责生成只读凭证报告。官方 API 和限制说明见 [docs/AWS_API.md](docs/AWS_API.md)。

- [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)：分页获取用户、组和绑定关系。
- [GetPolicyVersion](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicyVersion.html)：获取当前托管策略文档。
- [凭证报告](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)：AWS 最多每 4 小时重新生成，密码最后使用时间可能来自已有报告；手动获取不绕过此限制。
- [IP 条件语义](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)：保留操作符、IPv4/IPv6 和条件上下文。平台未计算 SCP、资源策略、会话策略以及所有请求上下文的最终授权结果。

控制台字段表示是否存在登录密码配置，不保证其他策略允许访问；MFA 字段表示是否关联 MFA 设备，不保证每次 API 调用均强制 MFA。`N/A`、`no_information` 等 AWS 值通过采集警告说明，不伪造最后使用时间。

## 本地运行与验证

Go 1.24 或更高版本；前端使用 Node.js 22.12+ 和其 `packageManager` 固定版本的 pnpm。

```bash
cp config.example.yaml config.yaml
go test ./...
go build -o audit-server ./cmd/audit-server
./audit-server -version
./audit-server -config config.yaml -check-config
./audit-server -config config.yaml
```

前端开发代理 `/api` 到 `127.0.0.1:10001`。生产环境构建前端后，将 `dist` 复制为配置指定的 `web_directory`，由 Go 同源托管；不需要单独运行 Vite。会话使用 HttpOnly、SameSite Cookie，写操作验证同源，登录失败有速率限制。

API：`POST /api/auth/login`、`GET /api/auth/me`、`POST /api/auth/logout`、`GET /api/dashboard`、`POST /api/sync`、`GET /api/sync/status`、`PATCH /api/users/{accountId}/{userId}/annotations`。除登录和健康检查，均需登录。手动获取返回 202；已有任务返回 409；未配置 AWS 账号返回清晰错误。无真实凭证时可验证登录、存储、调度、策略解析及 API，不能声称已通过真实 AWS 账号采集。

## 备份与更新

更新两个源码仓库后重新执行 `sudo bash install.sh`。旧配置和数据库会保留；更新前停服备份数据库，避免漏掉 SQLite WAL 中尚未合并的数据：

```bash
sudo systemctl stop aws-audit
sudo cp -a /var/lib/aws-audit /var/lib/aws-audit-backup-$(date +%Y%m%d-%H%M%S)
sudo cp -a /etc/aws-audit /etc/aws-audit-backup-$(date +%Y%m%d-%H%M%S)
sudo systemctl start aws-audit
```

备份包含账号信息和 AWS 凭证配置，应按服务器配置文件管理。

## 安装错误：缺少 libatomic.so.1

如果旧安装脚本在执行 npm 时出现 `node: error while loading shared libraries: libatomic.so.1`，在后端仓库中更新并重新安装：

```bash
git pull --ff-only
sudo bash install.sh
```

新脚本会自动安装缺少的依赖。也可先手动补齐运行库后重试：

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y libatomic1 libstdc++6

# RHEL / Rocky / Alma / Fedora（旧系统使用 yum）
sudo dnf install -y libatomic libstdc++
```

已有配置和数据库会保留。若错误包含 `GLIBC_x.y not found` 或 `GLIBCXX_x.y not found`，则是 Node.js 与系统 ABI 不兼容，需要满足对应 Node.js 版本的系统要求；仅安装 libatomic 不能解决该类错误。[Node.js 官方二进制系统要求](https://github.com/nodejs/node/blob/main/BUILDING.md#official-binary-platforms-and-toolchains)。

## SecretsManager 页面（RDS 主用户密码托管）

每次获取时，在 IAM 采集成功后按 `rds_regions`（留空=全部已启用区域）采集 RDS 实例/集群的主用户密码是否已迁移至 Secrets Manager，并通过 `DescribeSecret` 核验轮换配置（不读取密码值）。页面字段：账号名称、AWS 账号 ID、区域、实例/集群名称、主用户名、是否已迁移至 Secrets Manager、迁移核验结论、实际轮换周期、自动轮换、上次轮换时间（北京时间）、下次轮换最晚时间（北京时间）。采集身份需额外授予 `ec2:DescribeRegions`、`rds:DescribeDBInstances`、`rds:DescribeDBClusters`、`secretsmanager:DescribeSecret`，见 [deploy/iam-read-policy.json](deploy/iam-read-policy.json) 与 [docs/AWS_API.md](docs/AWS_API.md)。接口：`GET /api/rds-secrets`。
