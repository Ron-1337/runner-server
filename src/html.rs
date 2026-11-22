use crate::db::User;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use chrono::DateTime;

pub fn e(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// This service's version, `vX.Y.Z(B)-commit` (see `build.rs`). It is never in
/// a page: only a signed-in user is told it (GetMe, SignIn, a phone's approved
/// enrollment), and [version_script] shows it in the footer from there.
pub const VERSION: &str = env!("RUNNER_SERVER_VERSION");

/// Where the pages cache the version a signed-in response told them.
const VERSION_CACHE: &str = "runner-server-version";

/// Signed in: shows the cached version at once, then asks GetMe and caches
/// what it says. Signed out: forgets it, so it is not shown before signing in.
fn version_script(signed_in: bool) -> String {
    if !signed_in {
        return format!(
            "<script>try{{localStorage.removeItem('{VERSION_CACHE}')}}catch(e){{}}</script>"
        );
    }
    format!(
        r#"<script>(function(){{var k='{VERSION_CACHE}',el=document.getElementById('server-version');
function show(v){{if(v)el.textContent=v}}
try{{show(localStorage.getItem(k))}}catch(e){{}}
fetch('/api/runner_server.v1.AccountService/GetMe',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{}}',credentials:'same-origin'}})
.then(function(r){{return r.ok?r.json():null}}).then(function(me){{var v=me&&me.serverVersion;if(!v)return;
try{{localStorage.setItem(k,v)}}catch(e){{}}show(v)}}).catch(function(){{}})}})();</script>"#
    )
}

pub enum Notice {
    Ok(String),
    Err(String),
}

impl Notice {
    pub fn ok(m: impl Into<String>) -> Option<Self> {
        Some(Self::Ok(m.into()))
    }
    pub fn err(m: impl Into<String>) -> Option<Self> {
        Some(Self::Err(m.into()))
    }
}

pub fn time(ts: i64) -> String {
    DateTime::from_timestamp(ts, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

const STYLE: &str = r#"
*{box-sizing:border-box}body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#f6f7f9;color:#1f2328}
header{background:#fff;border-bottom:1px solid #e3e6ea}header .in{max-width:960px;margin:0 auto;padding:12px 20px;display:flex;gap:18px;align-items:center}
header b{font-size:16px;margin-right:auto}header a{color:#1f2328;text-decoration:none}header a:hover{text-decoration:underline}
main{max-width:960px;margin:28px auto;padding:0 20px}.card{background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:22px;margin-bottom:20px}
h1{font-size:22px;margin:0 0 16px}h2{font-size:17px;margin:0 0 12px}
label{display:block;margin:12px 0 4px;font-weight:600}input[type=text],input[type=password],select{width:100%;max-width:380px;padding:8px 10px;border:1px solid #cfd4da;border-radius:6px;font:inherit}
button{padding:7px 14px;border:1px solid #cfd4da;border-radius:6px;background:#fff;font:inherit;cursor:pointer}button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}button.danger{color:#cf222e}
form.inline{display:inline}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid #eef0f2;vertical-align:top}
.notice{padding:10px 14px;border-radius:6px;margin-bottom:18px}.ok{background:#dafbe1;color:#116329}.err{background:#ffebe9;color:#a40e26}
.muted{color:#656d76;font-size:13px}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.code{font-size:26px;letter-spacing:3px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.on{background:#1a7f37}.off{background:#afb8c1}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;background:#ddf4ff;color:#0969da;font-size:13px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
body{min-height:100vh;display:flex;flex-direction:column}main{flex:1;width:100%}
footer{border-top:1px solid #e3e6ea;background:#fff}footer .in{max-width:960px;margin:0 auto;padding:12px 20px;display:flex;gap:12px;justify-content:space-between;flex-wrap:wrap;color:#656d76;font-size:13px}
.boxes{display:flex;gap:6px;align-items:center;flex-wrap:nowrap}.boxes .box{width:2.4em;height:2.8em;padding:0;text-align:center;font:600 20px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;text-transform:uppercase;border:1px solid #cfd4da;border-radius:6px}
.boxes .box:focus{outline:2px solid #1f6feb;border-color:#1f6feb}.boxes .dash{font-size:22px;color:#656d76;padding:0 2px}
@media(max-width:420px){.boxes{gap:4px}.boxes .box{width:2em;height:2.4em;font-size:17px}}
"#;

pub fn page(title: &str, user: Option<&User>, notice: Option<Notice>, body: &str) -> Html<String> {
    let nav = match user {
        Some(u) => format!(
            r#"<a href="/hosts">设备管理</a><a href="/hosts/add">添加设备</a>{}<a href="/account">{}</a>
<form class="inline" method="post" action="/logout"><button>退出</button></form>"#,
            if u.is_admin {
                r#"<a href="/admin/users">用户管理</a>"#
            } else {
                ""
            },
            e(&u.display_name)
        ),
        None => String::new(),
    };
    let notice = match notice {
        Some(Notice::Ok(m)) => format!(r#"<div class="notice ok">{}</div>"#, e(&m)),
        Some(Notice::Err(m)) => format!(r#"<div class="notice err">{}</div>"#, e(&m)),
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Runner Server</title><style>{STYLE}</style></head>
<body><header><div class="in"><b>Runner Server</b>{nav}</div></header><main>{notice}{body}</main>
<footer><div class="in"><span>Runner Server</span><span class="mono" id="server-version"></span></div></footer>{script}</body></html>"#,
        title = e(title),
        script = version_script(user.is_some()),
    ))
}

pub fn forbidden(user: &User) -> Response {
    (
        StatusCode::FORBIDDEN,
        page(
            "无权访问",
            Some(user),
            Notice::err("只有系统管理员可以访问此页面。"),
            "",
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_version_names_the_build_and_commit() {
        // vX.Y.Z(B)-commit, with a six-character commit.
        let version = super::VERSION;
        let rest = version
            .strip_prefix(&format!("v{}(", env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| panic!("{version}"));
        let (build, commit) = rest.split_once(")-").unwrap_or_else(|| panic!("{version}"));
        assert!(
            !build.is_empty() && build.bytes().all(|b| b.is_ascii_digit()),
            "{version}"
        );
        assert_eq!(commit.len(), 6, "{version}");
        assert!(commit.bytes().all(|b| b.is_ascii_hexdigit()), "{version}");
    }
}
