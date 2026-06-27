# 🍯 蜜罐攻击态势仪表盘

> **[English Documentation / 英文文档 →](README.md)**

伪装成 Solana 验证节点的 **Cowrie SSH 蜜罐**，配备实时 Web 仪表盘，展示攻击者会话、地理定位和 LLM 生成的行为描述。

![Python 3](https://img.shields.io/badge/python-3.10+-blue)
![Cowrie](https://img.shields.io/badge/honeypot-cowrie-orange)
![LLM](https://img.shields.io/badge/LLM-Ollama%20%7C%20OpenAI-green)

## 功能概述

本项目运行一个伪装成配置错误的 Solana 验证节点的 SSH 蜜罐。当攻击者连接时，Cowrie 记录每次登录尝试、Shell 命令和文件下载。仪表盘处理这些日志并展示：

- **实时攻击地图** — 使用 Leaflet.js 可视化攻击者来源地
- **攻击者排行榜** — 按尝试次数排名的攻击者列表，含昵称和运营商信息
- **会话回放** — 攻击者登录后的操作记录，附带命令注释
- **LLM 行为描述** — 通过 Ollama 或 OpenAI 兼容 API 生成的攻击者行为自然语言摘要
- **凭证分析** — 最常见的用户名/密码组合
- **每日统计** — 会话数、独立 IP、成功率随时间的变化

## 架构

```
互联网 → 端口 22 (iptables NAT) → Cowrie 蜜罐 (沙箱)
                                       ↓
                                   JSON 日志
                                       ↓
                  generate.py (解析 + GeoIP + LLM 描述 + 渲染 HTML)
                                       ↓
                                 dashboard.html (自包含文件)
                                       ↓
                        serve.py ← nginx 反向代理 (HTTPS)

                  analytics.py (增量会话分析、地理追踪)
```

### 数据流

1. **Cowrie** 通过 iptables NAT 重定向在端口 22 捕获 SSH 连接，以 JSON 格式记录事件
2. **generate.py** 每 5 分钟通过 cron 运行，解析最近 7 天的日志，执行批量 GeoIP 查询，为有趣的会话生成 LLM 描述，渲染自包含 HTML 仪表盘
3. **serve.py** 在 localhost 上提供仪表盘服务，位于 nginx（TLS + HTTP 基本认证）之后
4. **analytics.py** 每 5 分钟运行，增量处理新日志条目，维护 30 天保留期的聚合统计

## 诱饵设计

蜜罐以 **Solana 验证节点** 为主题，吸引针对加密货币的攻击者：

- `.env` 中放置含助记词的假 Solana 钱包
- `.bash_history` 中植入凭证
- 逼真的验证节点配置文件（密钥对、质押账户、投票账户）
- 引诱探索的目录结构
- 假的 `solana-validator` systemd 服务

这种伪装非常有效——许多攻击者会专门尝试 Solana 相关凭证（`solana:solana`、`sol:validator`、`validator:validator`）。

## 核心特性

### 会话情报
- **三层描述系统：** 字典查找 → 正则模式匹配 → LLM 生成（通过 Ollama 或 OpenAI 兼容 API）
- **攻击者昵称：** 基于来源国和行为的国家主题名称（如 `tulip_sol`、`dragon_root`）
- **命令注释：** 每条命令的内联技术说明，解释其作用和攻击者意图
- **描述缓存：** LLM 描述被缓存以避免重复推理

### 健壮性
- **增量日志处理** — 字节偏移追踪，不重复读取整个日志文件
- **日志轮转检测** — 优雅处理文件大小变化（无行计数脆弱性）
- **原子文件写入** — 所有 JSON 缓存和仪表盘 HTML 使用临时文件 + `os.rename` 防止损坏
- **Gzip 感知解析** — 通过魔数字节检测轮转的 `.gz` 日志，而非文件扩展名
- **会话去重** — 通过 (session, timestamp, eventid) 去重事件
- **7 天滚动窗口** — 仪表盘展示近期活动，非全部历史数据
- **30 天数据保留** — 分析裁剪防止磁盘无限增长
- **LLM 健康检查** — LLM 不可用时优雅跳过描述生成，使用缓存/模式匹配的描述

### 安全加固
- **XSS 防护** — 所有攻击者控制的数据（用户名、密码、命令、运营商名称）在渲染前进行 HTML 转义
- **目录遍历防护** — `serve.py` 仅提供 `dashboard.html`；其他路径返回 404
- **HTTPS 速率限制** — nginx `limit_req` 在 HTTP 和 HTTPS 端点上防止暴力破解
- **本地绑定** — `serve.py` 仅绑定 `127.0.0.1`；nginx 处理外部访问
- **HTTP 基本认证** — 仪表盘受密码保护
- **输出无敏感数据** — 生成的 HTML 仅含攻击者 IP 及其活动，不含服务器配置

### 仪表盘界面
- 暗色黑客美学主题，带 CRT 扫描线效果
- 交互式 Leaflet.js 地图，带脉冲标记
- Chart.js 可视化凭证和攻击时间线
- 点击飞行：点击攻击者昵称可缩放到地图位置
- 移动端响应式布局
- 每 30 秒自动刷新

## 文件结构

```
honeypot-dashboard/
├── README.md
├── .gitignore
├── .env.example                # 环境变量配置模板
├── Dockerfile                  # Python 3.12 镜像
├── docker-compose.yml          # 容器化部署（主机网络）
├── Makefile                    # test / build / up / down / logs
├── requirements-test.txt       # pytest + syrupy + pytest-mock
├── app/
│   ├── generate.py             # 日志解析 + GeoIP + LLM + HTML 渲染
│   ├── serve.py                # HTTP 服务器 (localhost:9999, nginx 之后)
│   ├── analytics.py            # 增量分析（字节偏移追踪）
│   └── scheduler.py            # 容器监控（serve + 定期重新生成）
├── tests/                      # pytest 测试套件
└── data/                       # 运行时数据，挂载到 /data（已 gitignore）
    ├── dashboard.html          #   生成的仪表盘
    ├── description_cache.json  #   LLM 描述缓存
    ├── geoip_cache.json        #   GeoIP 查询缓存
    └── analytics.json          #   聚合分析数据
```

## 部署

### 前置条件

- 一台可暴露到互联网的 VPS 或服务器
- Docker + Docker Compose（推荐）— 或 Python 3.12+（裸机运行）
  （仪表盘使用 3.12 专属的 f-string 语法，3.10/3.11 无法解析）
- [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet 蜜罐
- LLM 后端（可选但推荐）：本地 [Ollama](https://ollama.ai/)，或任何 OpenAI 兼容 API（OpenAI、DeepSeek、OpenRouter 等）
- nginx + Let's Encrypt 用于 TLS

> 仪表盘在容器中运行（见下方 **Docker 部署**）。
> Cowrie 和 Ollama 保持为主机服务——Cowrie 是捕获流量的在线蜜罐，
> Ollama 是共享的 LLM 后端；容器通过主机网络与两者通信。
> 步骤 4-5（cron + systemd）仅用于裸机运行。

### 1. 安装 Cowrie

按照 [Cowrie 官方安装指南](https://cowrie.readthedocs.io/en/latest/INSTALL.html) 操作。关键步骤：

```bash
# 创建 cowrie 用户
sudo adduser --disabled-password cowrie

# 克隆并设置 Cowrie
sudo -u cowrie git clone https://github.com/cowrie/cowrie /home/cowrie/cowrie
cd /home/cowrie/cowrie
sudo -u cowrie python3 -m venv cowrie-env
sudo -u cowrie ./cowrie-env/bin/pip install -r requirements.txt

# 配置 Cowrie 监听高端口（如 2223）
# 然后通过 iptables 重定向端口 22：
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2223

# 先将真实 SSH 移到非标准端口！

# 原始 iptables 规则不会在重启后保留（Docker 守护进程会重建 nat 表并可能丢弃规则）。
# 安装捆绑的 systemd 单元以在每次启动时重新应用重定向（在 Docker 之后排序）：
sudo cp deploy/honeypot-redirect.service /etc/systemd/system/
sudo systemctl enable --now honeypot-redirect.service
```

### 2. 安装仪表盘

```bash
# 克隆本仓库
git clone https://github.com/brezgis/honeypot-dashboard.git /home/dashboard

# 安装 Ollama（可选，用于 LLM 描述）
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3.5:9b  # 或任何小模型

# 或者使用 OpenAI 兼容 API —— 在 .env 中设置 LLM_PROVIDER=openai
# 完整配置选项见 .env.example

# 仪表盘从 Cowrie 默认位置读取日志：
#   /home/cowrie/cowrie/var/log/cowrie/cowrie.json
# 如果 Cowrie 日志在其他位置，设置 COWRIE_LOG_PATH（见配置说明）。
```

### 3. 配置 nginx

HTTPS + Let's Encrypt 的 nginx 配置示例：

```nginx
limit_req_zone $binary_remote_addr zone=dashboard:10m rate=5r/s;

server {
    listen 443 ssl;
    server_name your-domain.example.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.example.com/privkey.pem;

    limit_req zone=dashboard burst=10 nodelay;
    auth_basic "Honeypot Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:9999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

创建密码文件：
```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd your-username
```

### 4. 设置 Cron 任务

```bash
# 以仪表盘用户运行（非 root）
crontab -e

# 每 5 分钟重新生成仪表盘
*/5 * * * * cd /home/dashboard/app && /usr/bin/python3 generate.py >> /var/log/honeypot-dashboard.log 2>&1

# 每 5 分钟运行分析（错开 2 分钟以避免冲突）
2-57/5 * * * * cd /home/dashboard/app && /usr/bin/python3 analytics.py >> /var/log/honeypot-analytics.log 2>&1
```

### 5. 启动服务器

```bash
# 以 systemd 服务或 screen/tmux 运行 serve.py
cd /home/dashboard/app
python3 serve.py
```

或创建 systemd 服务：
```ini
[Unit]
Description=Honeypot Dashboard Server
After=network.target

[Service]
User=dashboard
WorkingDirectory=/home/dashboard/app
ExecStart=/usr/bin/python3 serve.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Docker 部署（推荐）

仪表盘以单个容器形式发布，监控 `serve.py` 以及定期的 `generate.py` / `analytics.py` 运行（`app/scheduler.py`——无需主机 cron 或 systemd 单元）。使用**主机网络**，因此绑定 `127.0.0.1:9999` 并通过 `localhost:11434` 访问主机 Ollama——前方的 nginx 配置（步骤 3）无需更改。

Cowrie 和 Ollama 保持为主机服务；容器以只读方式挂载 Cowrie 的日志目录，并将缓存/输出写入绑定挂载的 `./data` 目录。

```bash
# 1. 将代码放到主机上
git clone https://github.com/brezgis/honeypot-dashboard.git /opt/honeypot-dashboard
cd /opt/honeypot-dashboard

# 2. 停止任何裸机仪表盘服务以释放端口 9999
sudo systemctl disable --now honeypot-dashboard.service   # 如果存在

# 3.（可选但推荐）用现有缓存初始化 ./data，避免首次运行时重新获取大量 GeoIP 查询/重新生成描述
mkdir -p data
sudo cp /home/dashboard/app/{geoip_cache.json,description_cache.json,analytics.json,dashboard.html} data/ 2>/dev/null || true

# 4. 构建并启动
docker compose up -d --build
docker compose logs -f --tail=50    # 查看首次 generate/analytics 运行
```

容器自动重启（`restart: unless-stopped`）。在匹配的 Python 3.12 容器中运行测试套件：`make test`。

### 容器配置（环境变量）

在 `docker-compose.yml` 中设置；相同的变量也适用于裸机运行。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `COWRIE_LOG_PATH` | `/home/cowrie/cowrie/var/log/cowrie/cowrie.json` | Cowrie JSON 日志位置（容器内为 `/cowrie-logs/cowrie.json`） |
| `HONEYPOT_DATA_DIR` | 脚本旁边 | 缓存、`analytics.json` 和 `dashboard.html` 的写入位置（容器内为 `/data`） |
| `LLM_PROVIDER` | `ollama` | LLM 后端：`ollama` / `openai` / `none` |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 端点（`LLM_PROVIDER=ollama` 时生效） |
| `OLLAMA_MODEL` | `qwen3.5:9b` | Ollama 模型名 |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | OpenAI 兼容 API 基础 URL（`LLM_PROVIDER=openai` 时生效） |
| `OPENAI_API_KEY` | *(空)* | OpenAI 兼容 API 密钥 |
| `OPENAI_MODEL` | `gpt-4.1-mini` | OpenAI 兼容模型名 |
| `SERVE_HOST` | `127.0.0.1` | `serve.py` 绑定地址（桥接网络时设为 `0.0.0.0`） |
| `SERVE_PORT` | `9999` | HTTP 服务器端口 |
| `REGEN_INTERVAL` | `300` | 仪表盘/分析重新生成间隔（秒） |
| `SERVE_REGEN_ON_START` | `1` | `serve.py` 启动时是否重新生成（调度器设为 `0`） |

容器以**非 root** 用户运行（uid 10001），并加入主机的 `cowrie` 组以读取日志。因此，绑定挂载的 `./data` 必须对该 uid 可写——在主机上执行一次：

```bash
sudo chown -R 10001:10001 data
```

### 持续运行（`deploy/`）

- **`honeypot-redirect.service`** + **`docker-honeypot-redirect.conf`** — 保持端口 22 → Cowrie(2223) 的 iptables 重定向在重启和 Docker 守护进程重启后持续生效（Docker 启动时重建 nat 表并可能丢弃规则）：

  ```bash
  sudo cp deploy/honeypot-redirect.service /etc/systemd/system/
  sudo systemctl enable --now honeypot-redirect.service
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo cp deploy/docker-honeypot-redirect.conf /etc/systemd/system/docker.service.d/honeypot-redirect.conf
  sudo systemctl daemon-reload
  ```

- **`honeypot-watchdog.sh`** — 当重定向丢失、容器停止、仪表盘停止重新生成或 Cowrie 停止捕获时，通过 Resend 发送邮件告警。安装、配置并设置 cron：

  ```bash
  sudo cp deploy/honeypot-watchdog.sh /usr/local/bin/ && sudo chmod 755 /usr/local/bin/honeypot-watchdog.sh
  sudo tee /etc/honeypot-watchdog.env >/dev/null <<'EOF'
  RESEND_API_KEY=re_...
  ALERT_FROM="Honeypot Watchdog <honeypot@mail.example.com>"
  ALERT_TO=you@example.com
  EOF
  sudo chmod 600 /etc/honeypot-watchdog.env
  /usr/local/bin/honeypot-watchdog.sh --test     # 确认邮件送达
  ( sudo crontab -l 2>/dev/null; echo '*/15 * * * * /usr/local/bin/honeypot-watchdog.sh' ) | sudo crontab -
  ```

## 配置说明

部分非环境变量设置位于各脚本顶部：

| 设置 | 文件 | 默认值 | 说明 |
|------|------|--------|------|
| `LOCAL_TZ` | `generate.py` | `America/New_York` | 仪表盘时间戳的时区 |
| `MIN_REGEN_INTERVAL` | `serve.py` | `30` | 按需重新生成的最小间隔（秒） |
| `RETENTION_DAYS` | `analytics.py` | `30` | 分析数据保留天数 |

### LLM 后端（支持三种模式）

通过 `LLM_PROVIDER` 切换 LLM 后端：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `LLM_PROVIDER` | `ollama` | `ollama` / `openai` / `none`（禁用 LLM） |

**Ollama（默认）：**

```yaml
LLM_PROVIDER: ollama
OLLAMA_URL: http://localhost:11434
OLLAMA_MODEL: qwen3.5:9b
```

**OpenAI 兼容 API（OpenAI、DeepSeek、OpenRouter 等）：**

```yaml
LLM_PROVIDER: openai
OPENAI_BASE_URL: https://api.openai.com/v1
OPENAI_API_KEY: sk-xxx
OPENAI_MODEL: gpt-4.1-mini
```

**DeepSeek：**

```yaml
LLM_PROVIDER: openai
OPENAI_BASE_URL: https://api.deepseek.com/v1
OPENAI_API_KEY: sk-xxx
OPENAI_MODEL: deepseek-chat
```

**禁用 LLM：**

```yaml
LLM_PROVIDER: none
```

LLM 不可用时自动降级为规则描述，不影响仪表盘生成。

## 技术栈

- **[Cowrie](https://github.com/cowrie/cowrie)** — SSH/Telnet 蜜罐框架
- **Python 3** — 仪表盘生成、HTTP 服务、分析
- **[Ollama](https://ollama.ai/)** — 本地 LLM 推理（默认），或任何 OpenAI 兼容 API（OpenAI、DeepSeek 等）
- **[Leaflet.js](https://leafletjs.com/)** — 交互式攻击来源地图
- **[Chart.js](https://www.chartjs.org/)** — 凭证和时间线可视化
- **[ip-api.com](https://ip-api.com/)** — 批量 GeoIP 查询（免费套餐）
- **nginx** — 带 TLS 终止和速率限制的反向代理
- **Let's Encrypt** — 通过 certbot 获取免费 TLS 证书

## LLM 描述工作原理

描述系统采用三层方法以提高效率：

1. **第一层——命令注释**（即时）：字典将约 50 个常用命令映射为简短技术说明（如 `uname -a` → "操作系统/内核识别"）。加上约 40 个复合命令的正则模式。

2. **第二层——模式匹配**（即时）：基于正则的常见攻击模式分类。返回多样化的描述（每个类别 8+ 个选项，以 IP 哈希为种子实现确定性输出）。

3. **第三层——LLM 生成**（缓存）：对于不匹配已知模式的新会话，通过 few-shot 提示将会话详情发送给配置的 LLM（Ollama 或 OpenAI 兼容）。响应缓存在 `description_cache.json` 中，每个唯一会话仅描述一次。

提示使用 raw/few-shot 格式和真实示例，引导模型生成简洁、技术性强、有观点的描述。坏输出（元评论、拒绝、过短响应）会被检测和过滤。

## 作者

Anna Brezgis and Claude — [brezgis.com](https://brezgis.com)

## 许可证

MIT
