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
- “设备管理”：分别列出电脑和手机，查看在线状态和指纹，改名或移除设备。
- 手机通知：在 Runner Remote App 的“设置 → 通知”里选择推送方式（Bark、ntfy 或自定义 Webhook）和通知类型（需要输入、已完成、失败），可发送测试通知；网页的“通知设置”只显示当前方式并可发送测试。
- 会话监听：在 App 的“设置 → 通知 → 服务器监听”里，用电脑上 `runner remote pin` 显示的 PIN 让本服务以“Runner Remote 通知服务”的身份与电脑配对。电脑在线时，本服务保持一条只读的加密通道，只发送 `hello`、`overview` 和 `ping`，不输入也不接管。会话变为需要输入、完成（仅普通对话）或失败时推送，标题为 `Runner Remote`，内容为 `[需要输入]:会话名`、`[已完成]:会话名` 或 `[失败]:会话名`；Shell 会话不通知，每台电脑每分钟最多 30 条。通知只发给最后接管这个会话的手机（App 接管时上报 `ClaimSession`），没有人接管时发给最后连接这台电脑的手机。点开通知会用 `runner-remote://` 链接在 Runner Remote 中打开这个会话。配对密钥保存在服务的数据库中，可随时在 App 中取消配对，或在电脑上撤销这个设备。

## 构建

不依赖 Runner 源码。服务用到的协议类型和函数复制在 `src/protocol.rs`，`tests/fixtures/` 是 Runner 自己的报文样例，测试会检查两者一致；Runner 改协议时需要同步这两处。

```sh
cargo build --release
cargo test
```

## 下载

GitHub Actions 在每次推送到 `main` 和每个 PR 时运行测试，并编译以下产物（在该次运行的 Artifacts 中下载）：

| 平台 | 目标 |
| --- | --- |
| Linux amd64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| Windows amd64 | `x86_64-pc-windows-msvc` |
| macOS arm64 | `aarch64-apple-darwin` |

推送 `v*` 标签（如 `git tag v0.1.0 && git push origin v0.1.0`）会创建 GitHub Release，附带上述压缩包和 `SHA256SUMS`。

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

   手机 App 在系统登录浏览器里打开批准页，并在链接后加上 `app=1`。带这个参数时，批准或拒绝后页面会跳转到固定地址 `runner-remote-auth://enrollment?result=approved|denied`，登录浏览器随即关闭并回到 App；不带时页面照常显示结果。
3. 被控制的电脑设置 PIN：`runner remote pin`。
4. 在另一台电脑的 Runner 中打开远程电脑，首次连接输入 PIN 完成配对。

## 协议要点

| 路径 | 说明 |
| --- | --- |
| `POST /api/runner_server.v1.HostEnrollmentService/StartEnrollment` | 开始登录，返回 device code 与 user code（10 分钟有效）。手机按官方格式发 `"kind": "ENROLLMENT_KIND_CLIENT"`（或 `2`）和 `client`（`name`、`platform`、`osVersion`、`runnerVersion`）；旧的 `"kind": "phone"` 加 `host` 仍然接受。手机批准后立即可用，不出现在 `ListAccountHosts` 中，不能连 `/relay/host`，也不能作为连接目标；Runner 不发送 `kind`，按电脑处理 |
| `POST /api/runner_server.v1.HostEnrollmentService/PollEnrollment` | 轮询；批准后签发 `rhc_` 凭据（只返回一次），10 分钟内需连上中继。手机还会收到 `clientId`（与 `hostId` 相同） |
| `POST /api/runner_server.v1.HostEnrollmentService/SignOutHost` | 电脑注销 |
| `POST /api/runner_server.v1.HostEnrollmentService/SignOutClient` | 手机注销，只接受手机的凭据 |
| `POST /api/runner_server.v1.HostClientService/ListAccountHosts` | 同账号电脑列表 |
| `GET /relay/host`（`runner-relay.v1`） | 电脑常驻连接；`hello` → `welcome`，二进制帧带 4 字节大端通道号 |
| `GET /relay/client?host=<id>`（`runner-client.v1`） | 打开一条到同账号电脑的通道，帧原样转发 |

### 网页端 API

与官方 Runner Hub 相同的 Connect RPC（JSON），路径为 `POST /api/runner_server.v1.<服务>/<方法>`，`Content-Type: application/json`，用网页登录的 Cookie 认证；带 `Origin` 头时必须与 `--origin` 一致。出错时返回 Connect 错误 JSON，`details` 里带 `runner_server.v1.ErrorDetail`（官方的 `ErrorCode`）。现有的 HTML 页面照常可用。

| 服务 | 方法 |
| --- | --- |
| `AuthService` | `SignIn`（`username`、`password`，不需要验证码）、`Refresh`、`SignOut`、`SignOutEverywhere` |
| `AccountService` | `GetMe`、`ChangePassword` |
| `HostService` | `ListHosts`、`ListClients`、`ListConnections`、`RenameHost`、`RemoveHost`、`RemoveClient`、`LookupEnrollment`、`ApproveEnrollment`（可带 `name` 给设备命名）、`DenyEnrollment` |
| `AdminService`（管理员） | `ListUsers`、`DeactivateUser`、`ReactivateUser`、`ResetPassword`（返回临时密码），以及本服务的扩展 `CreateUser`（`username`、`displayName`、`password`、`isAdmin`）、`SetAdmin`（`userId`、`isAdmin`）、`DeleteUser`（`userId`） |

本服务没有验证码、自助注册和邀请码，账号只能由管理员创建：`AuthService/GetCaptcha`、`AuthService/Register`、`AdminService/CreateInvite`、`ListInvites`、`RevokeInvite` 返回 `unimplemented`。首次初始化仍在网页 `/setup` 完成。管理员不能对自己执行停用、重置密码、改角色和删除。`LookupEnrollment` 显示的请求来源 IP 只在连接来自本机（反向代理）时才采用 `X-Forwarded-For`。

本服务对中继控制消息的扩展（Runner 原版会忽略）：

| 消息 | 方向 | 说明 |
| --- | --- | --- |
| `{"type":"channelOpen","channel":17,"device":{"id":"…","kind":"phone"}}` | 服务 → 电脑 | 多了 `device`：打开通道的设备 |
| `{"type":"notify","device":"…","session":"…","title":"…","body":"…"}` | 电脑 → 服务 | 通知同账号的一部手机；服务按该手机的通道推送，并附上打开该会话的链接。每个电脑连接每分钟最多 30 条 |

关闭码：4001 同一凭据在别处连接，4003 电脑被移除、账号被停用或删除，4413 通道队列超过 1 MiB，1012 服务重启。服务每 25 秒发送 ping，60 秒无数据断开连接。

## 许可证

MIT，见 [LICENSE](LICENSE)。`src/protocol.rs` 和 `tests/fixtures/` 改编自 Runner（MIT，见 `licenses/runner-LICENSE`）。
