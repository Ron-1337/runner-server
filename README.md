# Runner Server

自托管的 Runner 远程访问服务：账号、电脑登录（device flow）和端到端加密通道的中继。与 Runner 客户端的协议兼容，客户端无需修改：

```sh
runner remote login --server https://runner.example.com
```

中继只按账号路由和转发字节。终端内容由 Runner 两端用 Noise 加密，PIN 配对也在两端完成，服务器拿不到密钥（见 Runner 仓库 `docs/tech/remote-control.md`）。

## 功能

- 首次打开时进入 `/setup`，创建的第一个账号是系统管理员；之后配置页关闭。
- 用户名密码登录（argon2 哈希，Cookie 会话，登录失败限流）。
- 管理员在“用户管理”中添加用户、重置密码、设为或取消管理员、停用、删除。停用或删除会立即断开该用户的所有电脑。
- 每个用户只能看到和连接自己账号下的电脑。
- “我的电脑”：查看在线状态和指纹，移除电脑。

## 构建

依赖 Runner 仓库中的 `runner-core`（协议类型直接复用），默认按同级目录 `../runner` 引用：

```sh
cargo build --release
cargo test
```

## 运行

```sh
runner-server --origin https://runner.example.com --listen 127.0.0.1:8080 --db /var/lib/runner-server/runner-server.db
```

| 参数 | 环境变量 | 默认值 |
| --- | --- | --- |
| `--origin` | `RUNNER_SERVER_ORIGIN` | `http://localhost:8080` |
| `--listen` | `RUNNER_SERVER_LISTEN` | `127.0.0.1:8080` |
| `--db` | `RUNNER_SERVER_DB` | `runner-server.db` |

`--origin` 必须与用户在浏览器和 `runner remote login --server` 中使用的地址完全一致（含端口）：它决定返回给客户端的链接和 `wss://…/relay/host`，也用于网页表单的跨站校验。Runner 只接受 HTTPS 的 origin，本机测试可用 `http://localhost:<port>` 或 `http://127.0.0.1:<port>`。

忘记管理员密码时，在服务器上执行（从标准输入读取新密码，用户不存在则创建）：

```sh
echo 'new-password' | runner-server --db /var/lib/runner-server/runner-server.db set-password alice --admin
```

日志级别用 `RUST_LOG` 控制，例如 `RUST_LOG=runner_server=debug`。服务收到 SIGTERM 时会以 1012 关闭所有电脑的连接，电脑会在 1–10 秒后自动重连。

## 反向代理

TLS 由反向代理负责，并且要支持 WebSocket、关闭缓冲。

Caddy：

```caddyfile
runner.example.com {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

nginx：

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;
}
```

（`$connection_upgrade` 需在 `http` 块中定义：`map $http_upgrade $connection_upgrade { default upgrade; '' close; }`。）

## 使用流程

1. 管理员打开 `https://runner.example.com` 完成初始化，然后在“用户管理”中添加用户。
2. 每台电脑（无论是被控制的还是用来控制的）运行 `runner remote login --server https://runner.example.com`，在浏览器中打开显示的链接，登录并批准，核对代码和指纹，再回到终端确认账号。
3. 被控制的电脑设置 PIN：`runner remote pin`。
4. 在另一台电脑的 Runner 中打开远程电脑，首次连接输入 PIN 完成配对。

## 协议要点

| 路径 | 说明 |
| --- | --- |
| `POST /api/runner_server.v1.HostEnrollmentService/StartEnrollment` | 开始登录，返回 device code 与 user code（10 分钟有效） |
| `POST /api/runner_server.v1.HostEnrollmentService/PollEnrollment` | 轮询；批准后签发 `rhc_` 凭据（只返回一次），10 分钟内需连上中继 |
| `POST /api/runner_server.v1.HostEnrollmentService/SignOutHost` | 电脑注销 |
| `POST /api/runner_server.v1.HostClientService/ListAccountHosts` | 同账号电脑列表 |
| `GET /relay/host`（`runner-relay.v1`） | 电脑常驻连接；`hello` → `welcome`，二进制帧带 4 字节大端通道号 |
| `GET /relay/client?host=<id>`（`runner-client.v1`） | 打开一条到同账号电脑的通道，帧原样转发 |

关闭码：4001 同一凭据在别处连接，4003 电脑被移除、账号被停用或删除，4413 通道队列超过 1 MiB，1012 服务重启。服务每 25 秒发送 ping，60 秒无数据断开连接。
