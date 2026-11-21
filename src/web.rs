use crate::{
    AppState,
    auth::{self, AdminUser, CurrentUser},
    db,
    html::{Notice, e, page, time},
    notify::{self, BARK_LEVELS, Bark, Channel},
    now,
    protocol::DeviceKind,
    relay, rpc,
};
use axum::{
    Form, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;

pub struct WebError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for WebError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        tracing::error!("request failed: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            page(
                "出错了",
                None,
                Notice::err("服务器内部错误，请稍后再试。"),
                "",
            ),
        )
            .into_response()
    }
}

type WebResult = Result<Response, WebError>;

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/setup", get(setup_page).post(setup_submit))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/hosts", get(hosts_page))
        .route("/hosts/add", get(add_page).post(add_submit))
        .route("/hosts/{id}/remove", post(remove_host))
        .route("/hosts/{id}/rename", post(rename_host))
        .route("/hosts/{id}/notify", get(notify_page).post(notify_submit))
        .route("/hosts/{id}/notify/test", post(notify_test))
        .route("/account", get(account_page).post(account_submit))
        .route("/admin/users", get(users_page).post(create_user))
        .route("/admin/users/{id}/{action}", post(user_action))
        .layer(middleware::from_fn_with_state(state, same_origin))
}

async fn same_origin(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if request.method() == Method::POST
        && let Some(origin) = request.headers().get(header::ORIGIN)
        && origin.to_str().ok() != Some(state.config.origin.as_str())
    {
        return (StatusCode::FORBIDDEN, "Cross-origin request rejected.").into_response();
    }
    next.run(request).await
}

fn with_cookie(mut response: Response, cookie: &str) -> WebResult {
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(cookie)?);
    Ok(response)
}

fn safe_next(next: Option<&str>) -> &str {
    match next {
        Some(n) if n.starts_with('/') && !n.starts_with("//") && !n.contains('\\') => n,
        _ => "/hosts",
    }
}

async fn user_count(state: &AppState) -> anyhow::Result<i64> {
    state.db.call(|c| db::user_count(c)).await
}

async fn index(State(state): State<AppState>, headers: axum::http::HeaderMap) -> WebResult {
    if user_count(&state).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    Ok(match auth::current_user(&state, &headers).await? {
        Some(_) => Redirect::to("/hosts"),
        None => Redirect::to("/login"),
    }
    .into_response())
}

fn setup_form(notice: Option<Notice>, username: &str, display: &str) -> Response {
    page(
        "初始化配置",
        None,
        notice,
        &format!(
            r#"<div class="card"><h1>初始化 Runner Server</h1>
<p class="muted">这是首次启动。创建的第一个账号将成为系统管理员，之后可以在“用户管理”中添加其他用户。</p>
<form method="post" action="/setup">
<label>用户名</label><input type="text" name="username" value="{}" required autofocus autocomplete="username">
<label>显示名称</label><input type="text" name="display_name" value="{}" placeholder="可选，默认同用户名">
<label>密码</label><input type="password" name="password" required autocomplete="new-password">
<label>确认密码</label><input type="password" name="confirm" required autocomplete="new-password">
<p><button class="primary">创建管理员</button></p></form></div>"#,
            e(username),
            e(display)
        ),
    )
    .into_response()
}

async fn setup_page(State(state): State<AppState>) -> WebResult {
    if user_count(&state).await? > 0 {
        return Ok(Redirect::to("/login").into_response());
    }
    Ok(setup_form(None, "", ""))
}

#[derive(Deserialize)]
struct NewUserForm {
    username: String,
    #[serde(default)]
    display_name: String,
    password: String,
    #[serde(default)]
    confirm: Option<String>,
    #[serde(default)]
    is_admin: Option<String>,
}

impl NewUserForm {
    fn validate(&self) -> Result<(String, String), &'static str> {
        auth::new_user_fields(
            &self.username,
            &self.display_name,
            &self.password,
            self.confirm.as_deref().unwrap_or(&self.password),
        )
    }
}

async fn setup_submit(State(state): State<AppState>, Form(form): Form<NewUserForm>) -> WebResult {
    let (username, display) = match form.validate() {
        Ok(v) => v,
        Err(m) => {
            return Ok(setup_form(
                Notice::err(m),
                &form.username,
                &form.display_name,
            ));
        }
    };
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&form.password)).await??;
    let now = now();
    let created = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            if db::user_count(&tx)? > 0 {
                return Ok(None);
            }
            let id = db::insert_user(&tx, &username, &display, &hash, true, now)?;
            tx.commit()?;
            Ok(id)
        })
        .await?;
    let Some(id) = created else {
        return Ok(Redirect::to("/login").into_response());
    };
    tracing::info!("administrator account created");
    let token = auth::start_session(&state, id).await?;
    with_cookie(
        Redirect::to("/hosts").into_response(),
        &auth::session_cookie(&token, state.config.secure_cookies),
    )
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
}

fn login_form(notice: Option<Notice>, username: &str, next: &str) -> Response {
    page(
        "登录",
        None,
        notice,
        &format!(
            r#"<div class="card"><h1>登录</h1><form method="post" action="/login">
<input type="hidden" name="next" value="{}">
<label>用户名</label><input type="text" name="username" value="{}" required autofocus autocomplete="username">
<label>密码</label><input type="password" name="password" required autocomplete="current-password">
<p><button class="primary">登录</button></p></form>
<p class="muted">没有账号？请联系系统管理员为你创建。</p></div>"#,
            e(next),
            e(username)
        ),
    )
    .into_response()
}

async fn login_page(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<NextQuery>,
) -> WebResult {
    if user_count(&state).await? == 0 {
        return Ok(Redirect::to("/setup").into_response());
    }
    let next = safe_next(q.next.as_deref());
    if auth::current_user(&state, &headers).await?.is_some() {
        return Ok(Redirect::to(next).into_response());
    }
    Ok(login_form(None, "", next))
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    next: Option<String>,
}

async fn login_submit(State(state): State<AppState>, Form(form): Form<LoginForm>) -> WebResult {
    let next = safe_next(form.next.as_deref()).to_owned();
    let key = form.username.trim().to_lowercase();
    if !state.limiter.allowed(&key) {
        return Ok(login_form(
            Notice::err("登录失败次数过多，请 15 分钟后再试。"),
            &form.username,
            &next,
        ));
    }
    let lookup = form.username.trim().to_owned();
    let found = state
        .db
        .call(move |c| db::user_with_hash(c, &lookup))
        .await?;
    let password = form.password.clone();
    let (user, hash) = match found {
        Some((u, h)) => (Some(u), Some(h)),
        None => (None, None),
    };
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&password, hash.as_deref()))
            .await?;
    let user = match user {
        Some(u) if valid && !u.disabled => u,
        Some(u) if valid && u.disabled => {
            return Ok(login_form(
                Notice::err("该账号已被停用。"),
                &form.username,
                &next,
            ));
        }
        _ => {
            state.limiter.fail(&key);
            return Ok(login_form(
                Notice::err("用户名或密码错误。"),
                &form.username,
                &next,
            ));
        }
    };
    state.limiter.clear(&key);
    let token = auth::start_session(&state, user.id).await?;
    let id = user.id;
    state
        .db
        .call(move |c| db::touch_login(c, id, now()))
        .await?;
    with_cookie(
        Redirect::to(&next).into_response(),
        &auth::session_cookie(&token, state.config.secure_cookies),
    )
}

async fn logout(State(state): State<AppState>, headers: axum::http::HeaderMap) -> WebResult {
    if let Some(token) = auth::cookie_value(&headers, auth::SESSION_COOKIE) {
        let hash = auth::sha256_hex(&token);
        state.db.call(move |c| db::delete_session(c, &hash)).await?;
    }
    with_cookie(
        Redirect::to("/login").into_response(),
        &auth::clear_cookie(state.config.secure_cookies),
    )
}

#[derive(Deserialize)]
struct OkQuery {
    ok: Option<String>,
}

async fn hosts_page(
    State(state): State<AppState>,
    me: CurrentUser,
    Query(q): Query<OkQuery>,
) -> WebResult {
    let user_id = me.user.id;
    let hosts = state
        .db
        .call(move |c| db::hosts_for_user(c, user_id))
        .await?;
    let mut rows = String::new();
    for h in &hosts {
        let phone = h.kind == DeviceKind::Phone;
        let online = state.hub.connected_at(h.id);
        let status = match online {
            // A phone only opens client routes, so it is never "online" as a host.
            _ if phone => format!(
                r#"<span class="tag">手机</span><div class="muted">{}</div>"#,
                h.last_seen_at
                    .map(|t| format!("最后使用 {}", time(t)))
                    .unwrap_or_default()
            ),
            Some(t) => format!(
                r#"<span class="dot on"></span>在线<div class="muted">自 {}</div>"#,
                time(t.timestamp())
            ),
            None => format!(
                r#"<span class="dot off"></span>离线<div class="muted">{}</div>"#,
                h.last_seen_at
                    .map(|t| format!("最后在线 {}", time(t)))
                    .unwrap_or_default()
            ),
        };
        rows.push_str(&format!(
            r#"<tr><td><b>{name}</b><div class="muted">{platform} {arch} · {os} · Runner {version}</div></td>
<td class="mono">{fp}</td><td>{status}</td><td>{created}</td>
<td>{notify}<form class="inline row" method="post" action="/hosts/{id}/rename"><input type="text" name="name" value="{name}" required maxlength="64" style="width:160px"><button>改名</button></form>
<form class="inline" method="post" action="/hosts/{id}/remove" onsubmit="return confirm('确定移除这{noun}？它需要重新登录才能再使用远程访问。')"><button class="danger">移除</button></form></td></tr>"#,
            noun = if phone { "部手机" } else { "台电脑" },
            notify = if phone {
                format!(r#"<p><a href="/hosts/{}/notify">通知设置</a></p>"#, h.id)
            } else {
                String::new()
            },
            name = e(&h.name),
            platform = e(&h.info.platform),
            arch = e(&h.info.arch),
            os = e(&h.info.os_version),
            version = e(&h.info.runner_version),
            fp = e(&h.fingerprint),
            created = time(h.created_at),
            id = h.id,
        ));
    }
    let table = if hosts.is_empty() {
        r#"<p class="muted">还没有电脑。在电脑上运行下面的命令登录到本服务。</p>"#.to_owned()
    } else {
        format!(
            "<table><tr><th>电脑</th><th>指纹</th><th>状态</th><th>添加时间</th><th></th></tr>{rows}</table>"
        )
    };
    let notice = match q.ok.as_deref() {
        Some("removed") => Notice::ok("已移除该电脑。"),
        Some("renamed") => Notice::ok(
            "已改名。其他 Runner 刷新电脑列表后会显示新名字；这台电脑自己下次连接服务时更新。",
        ),
        Some("bad-name") => Notice::err("名字不能为空，且不超过 64 个字符。"),
        _ => None,
    };
    Ok(page(
        "我的电脑",
        Some(&me.user),
        notice,
        &format!(
            r#"<div class="card"><h1>我的电脑</h1>{table}</div>
<div class="card"><h2>连接一台电脑</h2><p>在要连接的电脑上运行：</p>
<p><code>runner remote login --server {origin}</code></p>
<p class="muted">命令会显示一个链接和代码，在浏览器中打开链接并批准即可。每台要控制别的电脑或被控制的电脑都需要登录一次。</p></div>"#,
            origin = e(&state.config.origin)
        ),
    )
    .into_response())
}

async fn remove_host(
    State(state): State<AppState>,
    me: CurrentUser,
    Path(id): Path<i64>,
) -> WebResult {
    let user_id = me.user.id;
    if state
        .db
        .call(move |c| db::delete_host(c, id, Some(user_id)))
        .await?
    {
        state.hub.kick(id, relay::CLOSE_REMOVED, "removed");
        tracing::info!(host = id, "host removed from web");
    }
    Ok(Redirect::to("/hosts?ok=removed").into_response())
}

#[derive(Deserialize)]
struct RenameForm {
    name: String,
}

pub fn clean_host_name(name: &str) -> Option<String> {
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim();
    (!name.is_empty() && name.chars().count() <= 64).then(|| name.to_owned())
}

async fn rename_host(
    State(state): State<AppState>,
    me: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<RenameForm>,
) -> WebResult {
    let Some(name) = clean_host_name(&form.name) else {
        return Ok(Redirect::to("/hosts?ok=bad-name").into_response());
    };
    let user_id = me.user.id;
    if state
        .db
        .call(move |c| db::rename_host(c, id, user_id, &name))
        .await?
    {
        tracing::info!(host = id, "host renamed from web");
    }
    Ok(Redirect::to("/hosts?ok=renamed").into_response())
}

#[derive(Deserialize)]
struct CodeQuery {
    code: Option<String>,
    /// `1` when the phone app opened this page in its sign-in browser: the
    /// decision then returns to the app through [APP_CALLBACK].
    app: Option<String>,
}

/// Where the phone app's sign-in browser closes and returns to the app. Fixed,
/// so the page cannot be made to redirect anywhere else.
pub const APP_CALLBACK: &str = "runner-remote-auth://enrollment";

fn code_form(user: &db::User, notice: Option<Notice>) -> Response {
    page(
        "添加电脑",
        Some(user),
        notice,
        r#"<div class="card"><h1>添加电脑</h1><form method="get" action="/hosts/add">
<label>输入电脑上显示的代码</label><input type="text" name="code" placeholder="XXXX-XXXX" required autofocus autocomplete="off">
<p><button class="primary">继续</button></p></form></div>"#,
    )
    .into_response()
}

async fn add_page(
    State(state): State<AppState>,
    me: CurrentUser,
    Query(q): Query<CodeQuery>,
) -> WebResult {
    let Some(raw) = q.code.filter(|c| !c.trim().is_empty()) else {
        return Ok(code_form(&me.user, None));
    };
    let Some(code) = auth::normalize_user_code(&raw) else {
        return Ok(code_form(&me.user, Notice::err("代码格式不正确。")));
    };
    let lookup = code.clone();
    let enrollment = state
        .db
        .call(move |c| db::enrollment_by_code(c, &lookup))
        .await?;
    let now = now();
    let Some(en) = enrollment.filter(|en| en.state == "pending" && en.expires_at > now) else {
        return Ok(code_form(
            &me.user,
            Notice::err("代码无效、已使用或已过期，请在电脑上重新运行登录命令。"),
        ));
    };
    let fingerprint = rpc::decode_host_key(&en.host_key)
        .map(|k| crate::protocol::fingerprint(&k))
        .unwrap_or_default();
    let from_app = q.app.as_deref() == Some("1");
    let (noun, title, shown_on) = match en.kind {
        DeviceKind::Computer => ("台电脑", "批准电脑", "电脑终端"),
        DeviceKind::Phone => ("部手机", "批准手机", "手机 App"),
    };
    Ok(page(
        title,
        Some(&me.user),
        None,
        &format!(
            r#"<div class="card"><h1>批准这{noun}？</h1>
<p class="code mono">{code}</p>
<table><tr><th>设备名</th><td>{name}</td></tr><tr><th>系统</th><td>{platform} {arch} · {os}</td></tr>
<tr><th>版本</th><td>{version}</td></tr><tr><th>指纹</th><td class="mono">{fp}</td></tr>
<tr><th>请求来源</th><td class="mono">{ip}</td></tr>
<tr><th>有效期至</th><td>{expires}</td></tr></table>
<p class="muted">请确认代码和指纹与{shown_on}中显示的一致。批准后这{noun}会加入账号 <b>{account}</b>。</p>
<form method="post" action="/hosts/add"><input type="hidden" name="code" value="{code}">{app}
<label>设备名称</label><input type="text" name="name" value="{name}" maxlength="64" autocomplete="off">
<p class="row"><button class="primary" name="decision" value="approve">批准</button><button name="decision" value="deny">拒绝</button></p></form></div>"#,
            code = e(&en.user_code),
            name = e(&en.info.hostname),
            platform = e(&en.info.platform),
            arch = e(&en.info.arch),
            os = e(&en.info.os_version),
            version = e(&en.info.runner_version),
            fp = e(&fingerprint),
            ip = e(&en.requesting_ip),
            expires = time(en.expires_at),
            account = e(&me.user.username),
            app = if from_app {
                r#"<input type="hidden" name="app" value="1">"#
            } else {
                ""
            },
        ),
    )
    .into_response())
}

#[derive(Deserialize)]
struct DecisionForm {
    code: String,
    decision: String,
    /// The device's name as approved; empty keeps the name it sent.
    #[serde(default)]
    name: String,
    #[serde(default)]
    app: String,
}

async fn add_submit(
    State(state): State<AppState>,
    me: CurrentUser,
    Form(form): Form<DecisionForm>,
) -> WebResult {
    let Some(code) = auth::normalize_user_code(&form.code) else {
        return Ok(code_form(&me.user, Notice::err("代码格式不正确。")));
    };
    let approve = form.decision == "approve";
    let name = match form.name.trim() {
        _ if !approve => None,
        "" => None,
        raw => match clean_host_name(raw) {
            Some(name) => Some(name),
            None => {
                return Ok(code_form(
                    &me.user,
                    Notice::err("设备名称不超过 64 个字符。"),
                ));
            }
        },
    };
    let user_id = me.user.id;
    let decided = state
        .db
        .call(move |c| db::decide_enrollment(c, &code, approve, user_id, name.as_deref(), now()))
        .await?;
    if !decided {
        return Ok(code_form(
            &me.user,
            Notice::err("代码无效、已使用或已过期，请在电脑上重新运行登录命令。"),
        ));
    }
    if form.app == "1" {
        let result = if approve { "approved" } else { "denied" };
        return Ok(Redirect::to(&format!("{APP_CALLBACK}?result={result}")).into_response());
    }
    let (title, message) = if approve {
        (
            "已批准",
            "已批准。请回到电脑终端或手机 App 确认账号，完成后它会出现在“我的电脑”中。",
        )
    } else {
        ("已拒绝", "已拒绝这次登录请求。")
    };
    Ok(page(
        title,
        Some(&me.user),
        Notice::ok(message),
        r#"<p><a href="/hosts">返回我的电脑</a></p>"#,
    )
    .into_response())
}

fn account_form(user: &db::User, notice: Option<Notice>) -> Response {
    page(
        "账号",
        Some(user),
        notice,
        &format!(
            r#"<div class="card"><h1>账号</h1><p>用户名：<b>{}</b>　显示名称：{}　角色：{}</p></div>
<div class="card"><h2>修改密码</h2><form method="post" action="/account">
<label>当前密码</label><input type="password" name="current" required autocomplete="current-password">
<label>新密码</label><input type="password" name="password" required autocomplete="new-password">
<label>确认新密码</label><input type="password" name="confirm" required autocomplete="new-password">
<p><button class="primary">修改密码</button></p></form>
<p class="muted">修改后，其他浏览器中的登录会失效。已连接的电脑不受影响。</p></div>"#,
            e(&user.username),
            e(&user.display_name),
            if user.is_admin { "系统管理员" } else { "普通用户" }
        ),
    )
    .into_response()
}

async fn account_page(me: CurrentUser) -> Response {
    account_form(&me.user, None)
}

#[derive(Deserialize)]
struct PasswordForm {
    current: String,
    password: String,
    confirm: String,
}

async fn account_submit(
    State(state): State<AppState>,
    me: CurrentUser,
    Form(form): Form<PasswordForm>,
) -> WebResult {
    if let Err(m) = auth::validate_password(&form.password, &form.confirm) {
        return Ok(account_form(&me.user, Notice::err(m)));
    }
    let user_id = me.user.id;
    let hash = state
        .db
        .call(move |c| db::password_hash(c, user_id))
        .await?;
    let current = form.current.clone();
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&current, hash.as_deref()))
            .await?;
    if !valid {
        return Ok(account_form(&me.user, Notice::err("当前密码不正确。")));
    }
    let new_hash =
        tokio::task::spawn_blocking(move || auth::hash_password(&form.password)).await??;
    let keep = me.session.clone();
    state
        .db
        .call(move |c| {
            db::set_password(c, user_id, &new_hash)?;
            db::delete_sessions(c, user_id, Some(&keep))
        })
        .await?;
    Ok(account_form(&me.user, Notice::ok("密码已修改。")))
}

async fn render_users(state: &AppState, me: &db::User, notice: Option<Notice>) -> WebResult {
    let users = state.db.call(|c| db::list_users(c)).await?;
    let mut rows = String::new();
    for u in &users {
        let is_me = u.id == me.id;
        let actions = if is_me {
            r#"<span class="muted">当前账号</span>"#.to_owned()
        } else {
            format!(
                r#"<div class="row">
<form class="inline row" method="post" action="/admin/users/{id}/password"><input type="password" name="password" placeholder="新密码" required autocomplete="new-password" style="width:140px"><button>重置密码</button></form>
<form class="inline" method="post" action="/admin/users/{id}/{admin_action}"><button>{admin_label}</button></form>
<form class="inline" method="post" action="/admin/users/{id}/{disable_action}"><button>{disable_label}</button></form>
<form class="inline" method="post" action="/admin/users/{id}/delete" onsubmit="return confirm('确定删除用户 {name_js}？其电脑会全部被移除。')"><button class="danger">删除</button></form></div>"#,
                id = u.id,
                admin_action = if u.is_admin { "demote" } else { "promote" },
                admin_label = if u.is_admin {
                    "取消管理员"
                } else {
                    "设为管理员"
                },
                disable_action = if u.disabled { "enable" } else { "disable" },
                disable_label = if u.disabled { "启用" } else { "停用" },
                name_js = e(&u.username),
            )
        };
        rows.push_str(&format!(
            "<tr><td><b>{}</b><div class=\"muted\">{}</div></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e(&u.username),
            e(&u.display_name),
            if u.is_admin { "管理员" } else { "用户" },
            if u.disabled { "已停用" } else { "正常" },
            time(u.created_at),
            actions
        ));
    }
    Ok(page(
        "用户管理",
        Some(me),
        notice,
        &format!(
            r#"<div class="card"><h1>用户管理</h1><table><tr><th>用户</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr>{rows}</table></div>
<div class="card"><h2>添加用户</h2><form method="post" action="/admin/users">
<label>用户名</label><input type="text" name="username" required autocomplete="off">
<label>显示名称</label><input type="text" name="display_name" placeholder="可选，默认同用户名">
<label>初始密码</label><input type="password" name="password" required autocomplete="new-password">
<label><input type="checkbox" name="is_admin" value="1"> 设为系统管理员</label>
<p><button class="primary">添加用户</button></p></form></div>"#
        ),
    )
    .into_response())
}

async fn users_page(State(state): State<AppState>, AdminUser(me): AdminUser) -> WebResult {
    render_users(&state, &me.user, None).await
}

async fn create_user(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Form(form): Form<NewUserForm>,
) -> WebResult {
    let (username, display) = match form.validate() {
        Ok(v) => v,
        Err(m) => return render_users(&state, &me.user, Notice::err(m)).await,
    };
    let is_admin = form.is_admin.is_some();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&form.password)).await??;
    let name = username.clone();
    let created = state
        .db
        .call(move |c| db::insert_user(c, &name, &display, &hash, is_admin, now()))
        .await?;
    let notice = match created {
        Some(_) => {
            tracing::info!(user = %username, "user created");
            Notice::ok(format!("已添加用户 {username}。"))
        }
        None => Notice::err(format!("用户名 {username} 已存在。")),
    };
    render_users(&state, &me.user, notice).await
}

#[derive(Deserialize)]
struct ActionForm {
    password: Option<String>,
}

async fn user_action(
    State(state): State<AppState>,
    AdminUser(me): AdminUser,
    Path((id, action)): Path<(i64, String)>,
    Form(form): Form<ActionForm>,
) -> WebResult {
    if id == me.user.id {
        return render_users(
            &state,
            &me.user,
            Notice::err("不能对当前登录的账号执行此操作。"),
        )
        .await;
    }
    let notice = match action.as_str() {
        "password" => {
            let password = form.password.unwrap_or_default();
            if let Err(m) = auth::validate_password(&password, &password) {
                return render_users(&state, &me.user, Notice::err(m)).await;
            }
            let hash =
                tokio::task::spawn_blocking(move || auth::hash_password(&password)).await??;
            state
                .db
                .call(move |c| {
                    db::set_password(c, id, &hash)?;
                    db::delete_sessions(c, id, None)
                })
                .await?;
            Notice::ok("密码已重置，该用户需要重新登录网页。")
        }
        "promote" | "demote" => {
            let admin = action == "promote";
            state.db.call(move |c| db::set_admin(c, id, admin)).await?;
            Notice::ok("角色已更新。")
        }
        "disable" => {
            crate::api::deactivate_user(&state, id).await?;
            Notice::ok("用户已停用，其电脑的连接已断开。")
        }
        "enable" => {
            state
                .db
                .call(move |c| db::set_disabled(c, id, false))
                .await?;
            Notice::ok("用户已启用。之前断开的电脑需要重新运行登录命令。")
        }
        "delete" => {
            crate::api::delete_user(&state, id).await?;
            Notice::ok("用户已删除。")
        }
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };
    tracing::info!(user = id, action = %action, "user updated by admin");
    render_users(&state, &me.user, notice).await
}

/// One of the signed-in user's phones, or None.
async fn my_phone(state: &AppState, user_id: i64, id: i64) -> anyhow::Result<Option<db::Host>> {
    let host = state.db.call(move |c| db::host_by_id(c, id)).await?;
    Ok(host.filter(|h| h.user_id == user_id && h.kind == DeviceKind::Phone))
}

fn not_found(user: &db::User) -> Response {
    (
        StatusCode::NOT_FOUND,
        page(
            "找不到",
            Some(user),
            Notice::err("找不到这部手机。"),
            r#"<p><a href="/hosts">返回我的电脑</a></p>"#,
        ),
    )
        .into_response()
}

fn notify_form(
    user: &db::User,
    phone: &db::Host,
    channel: Option<&Channel>,
    notice: Option<Notice>,
) -> Response {
    let bark = match channel {
        Some(Channel::Bark(b)) => b.clone(),
        None => Bark::default(),
    };
    let enabled = channel.is_some();
    let levels: String = BARK_LEVELS
        .iter()
        .map(|(value, label)| {
            format!(
                r#"<option value="{v}"{sel}>{l}</option>"#,
                v = e(value),
                l = e(label),
                sel = if *value == bark.level {
                    " selected"
                } else {
                    ""
                }
            )
        })
        .collect();
    let server = if bark.server.is_empty() {
        notify::DEFAULT_BARK_SERVER
    } else {
        &bark.server
    };
    let group = if enabled {
        bark.group.as_str()
    } else {
        "Runner"
    };
    page(
        "通知设置",
        Some(user),
        notice,
        &format!(
            r#"<div class="card"><h1>通知设置：{name}</h1>
<p class="muted">电脑上的会话需要你处理时，通知只发给最后连接这个会话的设备。最后连接的是这部手机时，通过下面的通道推送；点开通知会在 Runner Remote 中打开这个会话。</p>
<form method="post" action="/hosts/{id}/notify">
<label>通道</label>
<select name="channel"><option value="">不发送</option><option value="bark"{bark_selected}>Bark（iOS）</option></select>
<label>Bark 服务器</label><input type="text" name="server" value="{server}" placeholder="{default}">
<div class="muted">官方服务器 {default}，或自建的 bark-server 地址</div>
<label>Device Key</label><input type="text" name="device_key" value="{key}" autocomplete="off" class="mono">
<div class="muted">在 Bark App 首页复制推送地址，取 {default}/ 后面的那一段</div>
<label>分组</label><input type="text" name="group" value="{group}" maxlength="64">
<label>铃声</label><input type="text" name="sound" value="{sound}" maxlength="64" placeholder="留空用默认铃声，例如 minuet">
<label>中断级别</label><select name="level">{levels}</select>
<p><button class="primary">保存</button></p></form>
<form method="post" action="/hosts/{id}/notify/test"><button{test_disabled}>发送测试通知</button></form>
<p><a href="/hosts">返回我的电脑</a></p></div>"#,
            name = e(&phone.name),
            id = phone.id,
            bark_selected = if enabled { " selected" } else { "" },
            server = e(server),
            default = notify::DEFAULT_BARK_SERVER,
            key = e(&bark.device_key),
            group = e(group),
            sound = e(&bark.sound),
            test_disabled = if enabled { "" } else { " disabled" },
        ),
    )
    .into_response()
}

async fn notify_page(
    State(state): State<AppState>,
    me: CurrentUser,
    Path(id): Path<i64>,
    Query(q): Query<OkQuery>,
) -> WebResult {
    let Some(phone) = my_phone(&state, me.user.id, id).await? else {
        return Ok(not_found(&me.user));
    };
    let channel = state.db.call(move |c| db::notify_channel(c, id)).await?;
    let notice = match q.ok.as_deref() {
        Some("saved") => Notice::ok("已保存。"),
        Some("off") => Notice::ok("已关闭这部手机的通知。"),
        Some("sent") => Notice::ok("测试通知已发送，请查看手机。"),
        _ => None,
    };
    Ok(notify_form(&me.user, &phone, channel.as_ref(), notice))
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct NotifyForm {
    channel: String,
    server: String,
    device_key: String,
    group: String,
    sound: String,
    level: String,
}

async fn notify_submit(
    State(state): State<AppState>,
    me: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<NotifyForm>,
) -> WebResult {
    let Some(phone) = my_phone(&state, me.user.id, id).await? else {
        return Ok(not_found(&me.user));
    };
    let bark = Bark {
        server: form.server,
        device_key: form.device_key,
        group: form.group,
        sound: form.sound,
        level: form.level,
    };
    let channel = match form.channel.as_str() {
        "" => None,
        "bark" => match bark.clone().validate() {
            Ok(bark) => Some(Channel::Bark(bark)),
            Err(m) => {
                let draft = Channel::Bark(bark);
                return Ok(notify_form(&me.user, &phone, Some(&draft), Notice::err(m)));
            }
        },
        _ => {
            return Ok(notify_form(
                &me.user,
                &phone,
                None,
                Notice::err("未知的通道"),
            ));
        }
    };
    let off = channel.is_none();
    state
        .db
        .call(move |c| db::set_notify_channel(c, id, channel.as_ref(), now()))
        .await?;
    tracing::info!(host = id, off, "notification channel saved");
    let ok = if off { "off" } else { "saved" };
    Ok(Redirect::to(&format!("/hosts/{id}/notify?ok={ok}")).into_response())
}

async fn notify_test(
    State(state): State<AppState>,
    me: CurrentUser,
    Path(id): Path<i64>,
) -> WebResult {
    let Some(phone) = my_phone(&state, me.user.id, id).await? else {
        return Ok(not_found(&me.user));
    };
    let channel = state.db.call(move |c| db::notify_channel(c, id)).await?;
    let Some(channel) = channel else {
        return Ok(notify_form(
            &me.user,
            &phone,
            None,
            Notice::err("先选择通道并保存。"),
        ));
    };
    let message = notify::Message {
        title: "Runner 测试通知".into(),
        body: format!("{} 的通知设置正常。", phone.name),
        url: Some(notify::app_link(
            &state.config.origin,
            &me.user.username,
            None,
        )),
    };
    if let Err(err) = state.notifier.send(&channel, &message).await {
        return Ok(notify_form(
            &me.user,
            &phone,
            Some(&channel),
            Notice::err(format!("发送失败：{err:#}")),
        ));
    }
    Ok(Redirect::to(&format!("/hosts/{id}/notify?ok=sent")).into_response())
}
