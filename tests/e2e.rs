use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use runner_server::protocol::{self as remote, EnrollmentState, PollResponse, StartResponse};
use runner_server::{AppState, app, config::Config, db};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{self, Message, client::IntoClientRequest, http::HeaderValue},
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const WAIT: Duration = Duration::from_secs(10);

struct Server {
    origin: String,
    rpc: reqwest::Client,
    _dir: tempfile::TempDir,
}

async fn server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = db::Db::open(&dir.path().join("test.db")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let state = AppState::new(Config::new(&origin).unwrap(), db);
    let router = app(state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Server {
        origin,
        rpc: reqwest::Client::new(),
        _dir: dir,
    }
}

/// A phone's StartEnrollment, as the official Runner app sends it.
fn phone_request(name: &str) -> Value {
    json!({
        "kind": "ENROLLMENT_KIND_CLIENT",
        "client": {"platform": "ios", "runnerVersion": "0.1.0", "osVersion": "26.1", "name": name},
    })
}

fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap()
}

impl Server {
    async fn call(&self, path: &str, credential: Option<&str>, body: Value) -> reqwest::Response {
        let mut request = self
            .rpc
            .post(format!("{}/api/runner_server.v1.{path}", self.origin))
            .json(&body);
        if let Some(c) = credential {
            request = request.bearer_auth(c);
        }
        request.send().await.unwrap()
    }

    async fn form(
        &self,
        client: &reqwest::Client,
        path: &str,
        form: &[(&str, &str)],
    ) -> reqwest::Response {
        client
            .post(format!("{}{path}", self.origin))
            .form(form)
            .send()
            .await
            .unwrap()
    }

    async fn enroll(&self, browser: &reqwest::Client, name: &str, key: u8) -> (String, String) {
        let request = json!({
            "host": {"hostname": name, "platform": "linux", "arch": "x86_64", "osVersion": "Test", "runnerVersion": "0.20.2"},
            "hostKey": STANDARD.encode([key; 32]),
        });
        self.enroll_with(browser, request, key).await
    }

    async fn enroll_with(
        &self,
        browser: &reqwest::Client,
        request: Value,
        key: u8,
    ) -> (String, String) {
        self.enroll_key(browser, request, &[key; 32]).await
    }

    async fn enroll_key(
        &self,
        browser: &reqwest::Client,
        request: Value,
        key: &[u8],
    ) -> (String, String) {
        let phone = request["kind"] == "ENROLLMENT_KIND_CLIENT";
        let start: StartResponse = self
            .call("HostEnrollmentService/StartEnrollment", None, request)
            .await
            .json()
            .await
            .unwrap();
        assert!(
            start
                .verification_uri_complete
                .starts_with(&format!("{}/hosts/add?code=", self.origin))
        );
        let poll = |code: String| async move {
            self.call(
                "HostEnrollmentService/PollEnrollment",
                None,
                json!({ "deviceCode": code }),
            )
            .await
            .json::<PollResponse>()
            .await
            .unwrap()
        };
        assert_eq!(
            poll(start.device_code.0.clone()).await.state,
            EnrollmentState::Pending
        );

        let page = browser
            .get(&start.verification_uri_complete)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        if phone {
            assert!(!page.contains("指纹"), "a phone has no fingerprint");
        } else {
            assert!(
                page.contains(&remote::fingerprint(key)),
                "approval page shows the fingerprint"
            );
        }
        let approved = self
            .form(
                browser,
                "/hosts/add",
                &[("code", &start.user_code), ("decision", "approve")],
            )
            .await;
        assert!(approved.text().await.unwrap().contains("已批准"));

        let issued = poll(start.device_code.0.clone()).await;
        assert_eq!(issued.state, EnrollmentState::Approved);
        let kind = remote::credential_kind(&issued.credential.0);
        if phone {
            // As the official service answers a client, plus this service's version.
            assert_eq!(kind, Some(remote::DeviceKind::Phone));
            assert_eq!(
                issued.relay_url,
                format!("{}/relay/client", self.origin.replacen("http", "ws", 1))
            );
            assert!(issued.host_id.is_empty(), "a phone gets a clientId");
            assert!(!issued.client_id.is_empty());
            assert_eq!(issued.server_version, env!("CARGO_PKG_VERSION"));
        } else {
            assert_eq!(kind, Some(remote::DeviceKind::Computer));
            assert!(remote::valid_relay_url(&self.origin, &issued.relay_url));
            assert!(issued.client_id.is_empty() && issued.server_version.is_empty());
        }
        assert!(issued.account.is_some());
        assert!(
            chrono::DateTime::parse_from_rfc3339(issued.claim_expires_at.as_deref().unwrap())
                .is_ok()
        );
        assert_eq!(
            poll(start.device_code.0.clone()).await.state,
            EnrollmentState::Expired,
            "device codes are single use"
        );
        let id = if phone {
            issued.client_id
        } else {
            issued.host_id
        };
        (id, issued.credential.0)
    }

    /// Signs in a phone named [name] as the official app does.
    async fn enroll_phone(&self, browser: &reqwest::Client, name: &str) -> (String, String) {
        self.enroll_with(browser, phone_request(name), 0).await
    }

    /// A web API call from [client]'s browser session: status and JSON body.
    async fn web(&self, client: &reqwest::Client, path: &str, body: Value) -> (u16, Value) {
        let response = client
            .post(format!("{}/api/runner_server.v1.{path}", self.origin))
            .header("Origin", &self.origin)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    /// Creates the first account, alice, signed in on [client].
    async fn setup(&self, client: &reqwest::Client) {
        let created = self
            .form(
                client,
                "/setup",
                &[
                    ("username", "alice"),
                    ("password", "correct-horse"),
                    ("confirm", "correct-horse"),
                ],
            )
            .await;
        assert_eq!(created.url().path(), "/hosts");
    }

    /// The ids `ListAccountHosts` returns to this credential.
    async fn host_ids(&self, credential: &str) -> Vec<String> {
        let hosts: Value = self
            .call(
                "HostClientService/ListAccountHosts",
                Some(credential),
                json!({}),
            )
            .await
            .json()
            .await
            .unwrap();
        hosts["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["id"].as_str().unwrap().to_owned())
            .collect()
    }

    async fn ws(
        &self,
        path: &str,
        credential: &str,
        protocol: &str,
    ) -> Result<Ws, Box<tungstenite::Error>> {
        let url = format!("{}{path}", self.origin.replacen("http", "ws", 1));
        let mut request = url.into_client_request().unwrap();
        let headers = request.headers_mut();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {credential}")).unwrap(),
        );
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_str(protocol).unwrap(),
        );
        let (socket, response) = connect_async(request).await.map_err(Box::new)?;
        assert_eq!(response.headers()["Sec-WebSocket-Protocol"], protocol);
        Ok(socket)
    }

    async fn host(&self, credential: &str) -> (Ws, Value) {
        let mut socket = self
            .ws("/relay/host", credential, remote::SUBPROTOCOL)
            .await
            .unwrap();
        let hello =
            json!({"type": "hello", "host": {"hostname": "renamed"}, "features": ["channels"]});
        socket
            .send(Message::Text(hello.to_string().into()))
            .await
            .unwrap();
        let welcome = text(&mut socket).await;
        (socket, welcome)
    }
}

async fn next(socket: &mut Ws) -> Message {
    loop {
        match timeout(WAIT, socket.next())
            .await
            .expect("socket message")
            .expect("socket open")
            .unwrap()
        {
            Message::Ping(_) | Message::Pong(_) => continue,
            message => return message,
        }
    }
}

async fn text(socket: &mut Ws) -> Value {
    match next(socket).await {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text, got {other:?}"),
    }
}

async fn binary(socket: &mut Ws) -> Vec<u8> {
    match next(socket).await {
        Message::Binary(b) => b.to_vec(),
        other => panic!("expected binary, got {other:?}"),
    }
}

async fn close_code(socket: &mut Ws) -> u16 {
    match next(socket).await {
        Message::Close(Some(frame)) => u16::from(frame.code),
        other => panic!("expected close, got {other:?}"),
    }
}

fn refused_status(result: Result<Ws, Box<tungstenite::Error>>) -> u16 {
    match result.map_err(|e| *e) {
        Err(tungstenite::Error::Http(response)) => response.status().as_u16(),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("connection unexpectedly accepted"),
    }
}

#[tokio::test]
async fn setup_enroll_and_relay_between_two_computers() {
    let s = server().await;
    let admin = browser();

    let first = admin.get(&s.origin).send().await.unwrap();
    assert_eq!(first.url().path(), "/setup");
    let created = s
        .form(
            &admin,
            "/setup",
            &[
                ("username", "alice"),
                ("display_name", "Alice"),
                ("password", "correct-horse"),
                ("confirm", "correct-horse"),
            ],
        )
        .await;
    assert_eq!(created.url().path(), "/hosts");
    let again = browser()
        .get(format!("{}/setup", s.origin))
        .send()
        .await
        .unwrap();
    assert_eq!(
        again.url().path(),
        "/login",
        "setup closes once an administrator exists"
    );

    let (a_id, a_cred) = s.enroll(&admin, "studio", 1).await;
    let (b_id, b_cred) = s.enroll(&admin, "laptop", 2).await;

    let (mut host_a, welcome) = s.host(&a_cred).await;
    assert_eq!(welcome["type"], "welcome");
    assert_eq!(welcome["hostId"], a_id.as_str());
    assert_eq!(welcome["name"], "studio");
    assert_eq!(welcome["account"]["username"], "alice");
    let (_host_b, _) = s.host(&b_cred).await;

    let hosts: Value = s
        .call(
            "HostClientService/ListAccountHosts",
            Some(&b_cred),
            json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    let hosts = hosts["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 2);
    let a = hosts.iter().find(|h| h["id"] == a_id.as_str()).unwrap();
    assert_eq!(a["online"], true);
    assert_eq!(a["self"], false);
    assert_eq!(a["fingerprint"], remote::fingerprint(&[1; 32]));
    assert_eq!(a["info"]["hostname"], "renamed");
    assert_eq!(
        hosts.iter().find(|h| h["id"] == b_id.as_str()).unwrap()["self"],
        true
    );

    let route = format!("/relay/client?host={a_id}");
    let mut client = s
        .ws(&route, &b_cred, remote::CLIENT_SUBPROTOCOL)
        .await
        .unwrap();
    let open = text(&mut host_a).await;
    assert_eq!(open["type"], "channelOpen");
    let ch = open["channel"].as_u64().unwrap() as u32;
    client
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(binary(&mut host_a).await, remote::wrap(ch, &[1, 2, 3]));
    host_a
        .send(Message::Binary(remote::wrap(ch, &[9, 9]).into()))
        .await
        .unwrap();
    assert_eq!(binary(&mut client).await, vec![9, 9]);

    let closing = json!({"type": "closeChannel", "channel": ch});
    host_a
        .send(Message::Text(closing.to_string().into()))
        .await
        .unwrap();
    assert_eq!(close_code(&mut client).await, 1000);

    let mut second = s
        .ws(&route, &b_cred, remote::CLIENT_SUBPROTOCOL)
        .await
        .unwrap();
    let reopened = text(&mut host_a).await;
    assert_eq!(reopened["type"], "channelOpen");
    second.close(None).await.unwrap();
    let closed = text(&mut host_a).await;
    assert_eq!(closed["type"], "channelClosed");
    assert_eq!(closed["channel"], reopened["channel"]);

    assert_eq!(
        refused_status(s.ws(&route, &b_cred, remote::SUBPROTOCOL).await),
        400,
        "client routes require the client subprotocol"
    );

    let (mut replacement, _) = s.host(&a_cred).await;
    assert_eq!(
        close_code(&mut host_a).await,
        4001,
        "a second connection replaces the first"
    );

    let removed = s.form(&admin, &format!("/hosts/{a_id}/remove"), &[]).await;
    assert_eq!(removed.url().path(), "/hosts");
    assert_eq!(close_code(&mut replacement).await, 4003);
    assert_eq!(
        refused_status(s.ws("/relay/host", &a_cred, remote::SUBPROTOCOL).await),
        401
    );
    let listed = s
        .call(
            "HostClientService/ListAccountHosts",
            Some(&a_cred),
            json!({}),
        )
        .await;
    assert_eq!(listed.status(), 401);
    assert_eq!(
        listed.json::<Value>().await.unwrap()["code"],
        "unauthenticated"
    );
}

#[tokio::test]
async fn users_are_isolated_and_only_admins_manage_users() {
    let s = server().await;
    let admin = browser();
    s.form(
        &admin,
        "/setup",
        &[
            ("username", "alice"),
            ("password", "correct-horse"),
            ("confirm", "correct-horse"),
        ],
    )
    .await;
    let created = s
        .form(
            &admin,
            "/admin/users",
            &[
                ("username", "bob"),
                ("display_name", "Bob"),
                ("password", "battery-staple"),
            ],
        )
        .await;
    assert!(created.text().await.unwrap().contains("已添加用户 bob"));

    let bob = browser();
    let wrong = s
        .form(
            &bob,
            "/login",
            &[("username", "bob"), ("password", "nope-nope")],
        )
        .await;
    assert!(wrong.text().await.unwrap().contains("用户名或密码错误"));
    let login = s
        .form(
            &bob,
            "/login",
            &[
                ("username", "bob"),
                ("password", "battery-staple"),
                ("next", "/account"),
            ],
        )
        .await;
    assert_eq!(login.url().path(), "/account");
    assert_eq!(
        bob.get(format!("{}/admin/users", s.origin))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let (a_id, a_cred) = s.enroll(&admin, "alice-mac", 3).await;
    let (_c_id, c_cred) = s.enroll(&bob, "bob-pc", 4).await;
    let (_host_a, _) = s.host(&a_cred).await;
    let (_host_c, _) = s.host(&c_cred).await;
    let route = format!("/relay/client?host={a_id}");
    assert_eq!(
        refused_status(s.ws(&route, &c_cred, remote::CLIENT_SUBPROTOCOL).await),
        404
    );
    let bobs: Value = s
        .call(
            "HostClientService/ListAccountHosts",
            Some(&c_cred),
            json!({}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bobs["hosts"].as_array().unwrap().len(), 1);

    let forged = s
        .rpc
        .post(format!("{}/admin/users", s.origin))
        .header("Origin", "https://evil.example")
        .form(&[("username", "mallory"), ("password", "whatever-1")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
}

#[tokio::test]
async fn renaming_a_computer_changes_what_other_runners_see() {
    let s = server().await;
    let admin = browser();
    s.form(
        &admin,
        "/setup",
        &[
            ("username", "alice"),
            ("password", "correct-horse"),
            ("confirm", "correct-horse"),
        ],
    )
    .await;
    s.form(
        &admin,
        "/admin/users",
        &[("username", "bob"), ("password", "battery-staple")],
    )
    .await;
    let bob = browser();
    s.form(
        &bob,
        "/login",
        &[("username", "bob"), ("password", "battery-staple")],
    )
    .await;

    let (a_id, a_cred) = s.enroll(&admin, "studio", 6).await;
    let (_b_id, b_cred) = s.enroll(&admin, "laptop", 7).await;
    let (srv, id) = (&s, a_id.as_str());
    let list = |cred: String| async move {
        srv.call("HostClientService/ListAccountHosts", Some(&cred), json!({}))
            .await
            .json::<Value>()
            .await
            .unwrap()["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["id"] == id)
            .map(|h| h["name"].as_str().unwrap().to_owned())
    };
    let (_host, welcome) = s.host(&a_cred).await;
    assert_eq!(welcome["name"], "studio");
    assert_eq!(list(b_cred.clone()).await.as_deref(), Some("studio"));

    let renamed = s
        .form(
            &admin,
            &format!("/hosts/{a_id}/rename"),
            &[("name", "  工作室 Mac  ")],
        )
        .await;
    assert!(renamed.text().await.unwrap().contains("已改名"));
    assert_eq!(list(b_cred.clone()).await.as_deref(), Some("工作室 Mac"));

    let (_again, welcome) = s.host(&a_cred).await;
    assert_eq!(
        welcome["name"], "工作室 Mac",
        "the computer learns its new name when it reconnects"
    );

    let blank = s
        .form(&admin, &format!("/hosts/{a_id}/rename"), &[("name", "   ")])
        .await;
    assert!(blank.text().await.unwrap().contains("名字不能为空"));
    s.form(
        &bob,
        &format!("/hosts/{a_id}/rename"),
        &[("name", "hijacked")],
    )
    .await;
    assert_eq!(
        list(b_cred).await.as_deref(),
        Some("工作室 Mac"),
        "other users cannot rename it"
    );
}

#[tokio::test]
async fn disabling_a_user_disconnects_their_computers() {
    let s = server().await;
    let admin = browser();
    s.form(
        &admin,
        "/setup",
        &[
            ("username", "alice"),
            ("password", "correct-horse"),
            ("confirm", "correct-horse"),
        ],
    )
    .await;
    s.form(
        &admin,
        "/admin/users",
        &[("username", "bob"), ("password", "battery-staple")],
    )
    .await;
    let bob = browser();
    s.form(
        &bob,
        "/login",
        &[("username", "bob"), ("password", "battery-staple")],
    )
    .await;
    let (_id, cred) = s.enroll(&bob, "bob-pc", 5).await;
    let (mut host, _) = s.host(&cred).await;

    let users = admin
        .get(format!("{}/admin/users", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let bob_id = users
        .split("/admin/users/")
        .filter_map(|part| part.split_once("/disable"))
        .map(|(id, _)| id.to_owned())
        .next()
        .unwrap();
    s.form(&admin, &format!("/admin/users/{bob_id}/disable"), &[])
        .await;
    assert_eq!(close_code(&mut host).await, 4003);
    assert_eq!(
        refused_status(s.ws("/relay/host", &cred, remote::SUBPROTOCOL).await),
        401
    );
    let page = bob.get(format!("{}/hosts", s.origin)).send().await.unwrap();
    assert_eq!(
        page.url().path(),
        "/login",
        "disabled users lose their web sessions"
    );
}

#[tokio::test]
async fn phones_connect_to_computers_but_are_not_listed_as_computers() {
    let s = server().await;
    let admin = browser();
    s.form(
        &admin,
        "/setup",
        &[
            ("username", "alice"),
            ("password", "correct-horse"),
            ("confirm", "correct-horse"),
        ],
    )
    .await;

    let (pc_id, pc_cred) = s.enroll(&admin, "studio", 1).await;
    let (mut host, _) = s.host(&pc_cred).await;
    let (phone_id, phone_cred) = s.enroll_phone(&admin, "Alice's iPhone").await;

    assert_eq!(
        s.host_ids(&pc_cred).await,
        vec![pc_id.clone()],
        "computers do not see the phone"
    );
    assert_eq!(
        s.host_ids(&phone_cred).await,
        vec![pc_id.clone()],
        "the phone sees only computers, not itself"
    );

    // A phone is active without ever connecting as a host, so it survives the purge
    // after its claim expires (10 minutes; the web session lasts 30 days).
    {
        let db = db::Db::open(&s._dir.path().join("test.db")).unwrap();
        db::purge(&db.lock(), chrono::Utc::now().timestamp() + 3600).unwrap();
    }
    assert_eq!(s.host_ids(&phone_cred).await, vec![pc_id.clone()]);

    assert_eq!(
        refused_status(s.ws("/relay/host", &phone_cred, remote::SUBPROTOCOL).await),
        403,
        "a phone cannot register as a host"
    );
    assert_eq!(
        refused_status(
            s.ws(
                &format!("/relay/client?host={phone_id}"),
                &pc_cred,
                remote::CLIENT_SUBPROTOCOL
            )
            .await
        ),
        404,
        "a phone is not a route target"
    );

    let mut client = s
        .ws(
            &format!("/relay/client?host={pc_id}"),
            &phone_cred,
            remote::CLIENT_SUBPROTOCOL,
        )
        .await
        .unwrap();
    let open = text(&mut host).await;
    assert_eq!(open["type"], "channelOpen");
    let ch = open["channel"].as_u64().unwrap() as u32;
    client.send(Message::Binary(vec![7].into())).await.unwrap();
    assert_eq!(binary(&mut host).await, remote::wrap(ch, &[7]));

    let page = admin
        .get(format!("{}/hosts", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Alice&#39;s iPhone"), "{page}");
    assert!(
        page.contains("最后使用"),
        "the phone shows when it was last used"
    );

    let removed = s
        .form(&admin, &format!("/hosts/{phone_id}/remove"), &[])
        .await;
    assert_eq!(removed.url().path(), "/hosts");
    let listed = s
        .call(
            "HostClientService/ListAccountHosts",
            Some(&phone_cred),
            json!({}),
        )
        .await;
    assert_eq!(listed.status(), 401, "a removed phone is signed out");
}

/// A stand-in Bark server that records every push.
async fn fake_bark() -> (String, tokio::sync::mpsc::UnboundedReceiver<Value>) {
    use axum::{Json, Router, routing::post};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let router = Router::new().route(
        "/push",
        post(move |Json(body): Json<Value>| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(body);
                Json(json!({"code": 200, "message": "success"}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (origin, rx)
}

#[tokio::test]
async fn hosts_notify_the_phone_that_opened_a_channel_through_bark() {
    let s = server().await;
    let admin = browser();
    s.form(
        &admin,
        "/setup",
        &[
            ("username", "alice"),
            ("password", "correct-horse"),
            ("confirm", "correct-horse"),
        ],
    )
    .await;
    let (pc_id, pc_cred) = s.enroll(&admin, "studio", 1).await;
    let (mut host, _) = s.host(&pc_cred).await;
    let (phone_id, phone_cred) = s.enroll_phone(&admin, "iPhone").await;

    // The phone's channel is set from the app; the web page only shows it.
    let (bark, mut pushes) = fake_bark().await;
    let hosts = admin
        .get(format!("{}/hosts", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(hosts.contains(&format!("/hosts/{phone_id}/notify")));
    assert!(!hosts.contains(&format!("/hosts/{pc_id}/notify")));
    let missing = admin
        .get(format!("{}/hosts/{pc_id}/notify", s.origin))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let settings = |channel: Value| json!({"channel": channel, "events": {"input": true, "finished": false, "failed": true}});
    let bad = s
        .call(
            "NotifyService/SetSettings",
            Some(&phone_cred),
            settings(json!({"kind": "bark", "server": bark, "deviceKey": "no spaces"})),
        )
        .await;
    assert_eq!(bad.status(), 400);
    let bad: Value = bad.json().await.unwrap();
    assert!(
        bad["message"].as_str().unwrap().contains("Device Key 无效"),
        "{bad}"
    );
    let refused = s
        .call("NotifyService/GetSettings", Some(&pc_cred), json!({}))
        .await;
    assert_eq!(
        refused.status(),
        403,
        "only phones have notification settings"
    );
    let saved = s
        .call(
            "NotifyService/SetSettings",
            Some(&phone_cred),
            settings(json!({"kind": "bark", "server": bark, "deviceKey": "phone-key", "group": "Runner", "level": "timeSensitive"})),
        )
        .await;
    assert_eq!(saved.status(), 200);
    let got: Value = s
        .call("NotifyService/GetSettings", Some(&phone_cred), json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(got["channel"]["deviceKey"], "phone-key");
    assert_eq!(
        got["events"],
        json!({"input": true, "finished": false, "failed": true})
    );
    let page = admin
        .get(format!("{}/hosts/{phone_id}/notify", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Bark"), "{page}");

    let tested = s
        .call("NotifyService/Test", Some(&phone_cred), json!({}))
        .await;
    assert_eq!(tested.status(), 200);
    let test = timeout(WAIT, pushes.recv()).await.unwrap().unwrap();
    assert_eq!(test["device_key"], "phone-key");
    assert_eq!(test["level"], "timeSensitive");
    assert_eq!(test["title"], "Runner Remote");
    assert_eq!(test["icon"], format!("{}/icon.png", s.origin));

    // No page carries the version: a signed-in page fills it in from GetMe,
    // a signed-out one forgets it. The icon and the web link into the app are public.
    let version = env!("CARGO_PKG_VERSION");
    assert!(!page.contains(version), "{page}");
    assert!(page.contains("AccountService/GetMe"), "{page}");
    let login = reqwest::get(format!("{}/login", s.origin))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !login.contains(version) && !login.contains("GetMe"),
        "{login}"
    );
    assert!(login.contains("localStorage.removeItem"), "{login}");
    let icon = reqwest::get(format!("{}/icon.png", s.origin))
        .await
        .unwrap();
    assert_eq!(icon.headers()["content-type"], "image/png");
    assert!(icon.bytes().await.unwrap().starts_with(b"\x89PNG"));
    let go = reqwest::get(format!(
        "{}/go?user=alice&computer={pc_id}&session=s1",
        s.origin
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    assert!(
        go.contains(&format!(
            "runner-remote://open?server={}",
            url::form_urlencoded::byte_serialize(s.origin.as_bytes()).collect::<String>()
        )),
        "{go}"
    );
    assert!(
        go.contains(&format!("computer={pc_id}&amp;session=s1")),
        "{go}"
    );

    // channelOpen names the device behind the channel.
    let _client = s
        .ws(
            &format!("/relay/client?host={pc_id}"),
            &phone_cred,
            remote::CLIENT_SUBPROTOCOL,
        )
        .await
        .unwrap();
    let open = text(&mut host).await;
    assert_eq!(open["device"], json!({"id": phone_id, "kind": "phone"}));

    // The host names the phone; the service adds the link into the app.
    let notify = json!({"type": "notify", "device": phone_id, "session": "s1", "title": "Fix the build", "body": "需要你 · runner"});
    host.send(Message::Text(notify.to_string().into()))
        .await
        .unwrap();
    let push = timeout(WAIT, pushes.recv()).await.unwrap().unwrap();
    assert_eq!(push["title"], "Fix the build");
    assert_eq!(push["body"], "需要你 · runner");
    assert_eq!(push["group"], "Runner");
    let link = url::Url::parse(push["url"].as_str().unwrap()).unwrap();
    assert_eq!(link.scheme(), "runner-remote");
    assert_eq!(link.host_str(), Some("open"));
    let query: std::collections::HashMap<_, _> = link.query_pairs().into_owned().collect();
    assert_eq!(query["server"], s.origin);
    assert_eq!(query["user"], "alice");
    assert_eq!(query["computer"], pc_id);
    assert_eq!(query["session"], "s1");

    // A device that is not one of the account's phones gets nothing.
    for device in [pc_id.as_str(), "999"] {
        let notify = json!({"type": "notify", "device": device, "title": "x"});
        host.send(Message::Text(notify.to_string().into()))
            .await
            .unwrap();
    }
    // Turning the channel off stops pushes too.
    let off = s
        .call(
            "NotifyService/SetSettings",
            Some(&phone_cred),
            json!({"channel": null}),
        )
        .await;
    assert_eq!(off.status(), 200);
    let notify = json!({"type": "notify", "device": phone_id, "title": "x"});
    host.send(Message::Text(notify.to_string().into()))
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(500), pushes.recv())
            .await
            .is_err(),
        "no push for other devices or a phone without a channel"
    );
}

/// A stand-in ntfy or webhook server that records each request body.
async fn fake_hook() -> (
    String,
    tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
) {
    use axum::{Router, http::HeaderMap, routing::post};
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = post(move |headers: HeaderMap, body: String| {
        let tx = tx.clone();
        async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let _ = tx.send((auth, body));
            "{}"
        }
    });
    let router = Router::new()
        .route("/", handler.clone())
        .route("/{*path}", handler);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (origin, rx)
}

mod fake_runner {
    //! A minimal `runnerd` on the relay: pairs by PIN, accepts paired
    //! devices, answers `hello` and `overview`, and pushes status changes.
    use super::*;
    use runner_core::companion::channel::{self, HostPair, Kind, NoiseKeys, Records, Reject};
    use runner_core::remote::HostKey;
    use std::collections::HashMap;

    pub const PIN: &str = "482913";

    #[allow(clippy::large_enum_variant)]
    enum State {
        Pairing(HostPair),
        Open(Records),
    }

    /// Runs the host on [socket]; each value from [pushes] goes to every open channel.
    pub async fn run(
        mut socket: Ws,
        key: HostKey,
        mut pushes: tokio::sync::mpsc::UnboundedReceiver<Value>,
        requests: tokio::sync::mpsc::UnboundedSender<Value>,
    ) {
        let mut channels: HashMap<u32, State> = HashMap::new();
        let mut paired: Vec<Vec<u8>> = Vec::new();
        let keys = || NoiseKeys {
            private: &key.private,
            fixed_ephemeral: None,
        };
        loop {
            let mut out: Vec<(u32, Vec<u8>)> = Vec::new();
            tokio::select! {
                push = pushes.recv() => {
                    let Some(push) = push else { return };
                    for (ch, state) in channels.iter_mut() {
                        if let State::Open(records) = state {
                            records.queue(serde_json::to_vec(&push).unwrap()).unwrap();
                            while let Some(f) = records.next_frame().unwrap() {
                                out.push((*ch, f));
                            }
                        }
                    }
                }
                message = socket.next() => {
                    let Some(Ok(message)) = message else { return };
                    let Message::Binary(bytes) = message else { continue };
                    let (ch, frame) = channel::unwrap(&bytes).unwrap();
                    match (frame[0], channels.remove(&ch)) {
                        (k, None) if k == Kind::Pair as u8 => {
                            let (pair, reply) =
                                HostPair::start(keys(), PIN, frame, rand::random()).unwrap();
                            out.push((ch, reply));
                            channels.insert(ch, State::Pairing(pair));
                        }
                        (k, Some(State::Pairing(pair))) if k == Kind::PairFinish as u8 => {
                            match pair.finish(frame) {
                                Ok((transport, identity)) => {
                                    assert_eq!(identity.name, "Runner Remote 通知服务");
                                    paired.push(identity.public_key);
                                    channels.insert(ch, State::Open(Records::new(transport)));
                                }
                                Err(reject) => out.push((ch, reject.frame())),
                            }
                        }
                        (k, None) if k == Kind::Connect as u8 => {
                            match channel::connect(keys(), frame, |d| paired.iter().any(|p| p == d)) {
                                Ok((transport, accept, _)) => {
                                    out.push((ch, accept));
                                    channels.insert(ch, State::Open(Records::new(transport)));
                                }
                                Err(reject) => out.push((ch, reject.frame())),
                            }
                        }
                        (_, Some(State::Open(mut records))) => {
                            if let Some(request) = records.receive(frame).unwrap() {
                                let request: Value = serde_json::from_slice(&request).unwrap();
                                records.handled();
                                let _ = requests.send(request.clone());
                                for reply in answer(&request) {
                                    records.queue(serde_json::to_vec(&reply).unwrap()).unwrap();
                                }
                            }
                            while let Some(f) = records.next_frame().unwrap() {
                                out.push((ch, f));
                            }
                            channels.insert(ch, State::Open(records));
                        }
                        (_, None) => {}
                        _ => out.push((ch, Reject::BadHandshake.frame())),
                    }
                }
            }
            for (ch, frame) in out {
                if socket
                    .send(Message::Binary(channel::wrap(ch, &frame).into()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }

    fn answer(request: &Value) -> Vec<Value> {
        let id = &request["id"];
        match request["type"].as_str().unwrap_or_default() {
            "hello" => vec![
                json!({"type": "welcome", "version": 1, "name": "studio", "runnerVersion": "0.20.2", "platform": "linux", "features": ["ping"]}),
            ],
            "ping" => vec![json!({"type": "pong", "id": id})],
            "overview" => vec![json!({"type": "result", "id": id, "result": {
                "projects": [], "tabs": [], "missions": [], "sessions": {
                    "s1": {"kind": "chat", "title": "Fix the build", "runtime": "claude", "cwd": "/tmp", "status": "working", "reason": null, "unread": false},
                    "s2": {"kind": "chat", "title": "Docs", "runtime": "claude", "cwd": "/tmp", "status": "working", "reason": null, "unread": false}
                }
            }})],
            _ => {
                vec![json!({"type": "error", "id": id, "code": "unknownRequest", "message": "no"})]
            }
        }
    }
}

#[tokio::test]
async fn the_service_watches_sessions_and_notifies_the_phone_that_took_them_over() {
    use runner_core::remote::HostKey;
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let key = HostKey::generate().unwrap();
    let request = json!({
        "host": {"hostname": "studio", "platform": "linux"},
        "hostKey": STANDARD.encode(&key.public),
    });
    let (pc_id, pc_cred) = s.enroll_key(&admin, request, &key.public).await;
    let (host, _) = s.host(&pc_cred).await;
    let (push_tx, push_rx) = tokio::sync::mpsc::unbounded_channel();
    let (request_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(fake_runner::run(host, key, push_rx, request_tx));

    let (_, first) = s.enroll_phone(&admin, "First").await;
    let (_, second) = s.enroll_phone(&admin, "Second").await;
    let (hook, mut hooks) = fake_hook().await;
    for (cred, topic) in [(&first, "first"), (&second, "second")] {
        let saved = s
            .call(
                "NotifyService/SetSettings",
                Some(cred),
                json!({"channel": {"kind": "ntfy", "server": hook, "topic": topic, "token": "tk"}}),
            )
            .await;
        assert_eq!(saved.status(), 200);
    }

    // Pairing needs the computer's PIN, and only reads.
    let watchers: Value = s
        .call("NotifyService/ListWatchers", Some(&first), json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(watchers["watchers"][0]["computer"], pc_id);
    assert_eq!(watchers["watchers"][0]["paired"], false);
    let wrong = s
        .call(
            "NotifyService/PairWatcher",
            Some(&first),
            json!({"computer": pc_id, "pin": "000000"}),
        )
        .await;
    assert_eq!(wrong.status(), 400);
    let paired = s
        .call(
            "NotifyService/PairWatcher",
            Some(&first),
            json!({"computer": pc_id, "pin": fake_runner::PIN}),
        )
        .await;
    assert_eq!(paired.status(), 200, "{}", paired.text().await.unwrap());

    // The watcher says hello and asks for the overview, nothing else.
    let mut seen = Vec::new();
    while seen.iter().filter(|t: &&String| *t == "overview").count() < 1 {
        let request = timeout(WAIT, requests.recv()).await.unwrap().unwrap();
        seen.push(request["type"].as_str().unwrap().to_owned());
    }
    assert!(
        seen.iter()
            .all(|t| ["hello", "overview", "ping"].contains(&t.as_str())),
        "{seen:?}"
    );
    let listed: Value = s
        .call("NotifyService/ListWatchers", Some(&first), json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(listed["watchers"][0]["paired"], true);
    assert_eq!(listed["watchers"][0]["watching"], true);

    // The first phone took s1 over…
    let claimed = s
        .call(
            "NotifyService/ClaimSession",
            Some(&first),
            json!({"computer": pc_id, "session": "s1"}),
        )
        .await;
    assert_eq!(claimed.status(), 200);
    // …and the second phone connected after it, so it hears about the
    // sessions nobody took over.
    let _route = s
        .ws(
            &format!("/relay/client?host={pc_id}"),
            &second,
            remote::CLIENT_SUBPROTOCOL,
        )
        .await
        .unwrap();

    push_tx
        .send(json!({"type": "status", "session": "s1", "status": "needsYou", "reason": "approval", "unread": false}))
        .unwrap();
    let (auth, body) = timeout(WAIT, hooks.recv()).await.unwrap().unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(auth, "Bearer tk");
    assert_eq!(body["topic"], "first");
    assert_eq!(body["title"], "Runner Remote");
    assert_eq!(body["message"], "需要输入:Fix the build");
    assert!(body["click"].as_str().unwrap().contains("session=s1"));

    push_tx
        .send(json!({"type": "status", "session": "s2", "status": "idle", "reason": null, "unread": true}))
        .unwrap();
    let (_, body) = timeout(WAIT, hooks.recv()).await.unwrap().unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["topic"], "second");
    assert_eq!(body["message"], "已完成:Docs");

    // A phone that turned "failed" off is not told.
    let saved = s
        .call(
            "NotifyService/SetSettings",
            Some(&first),
            json!({"channel": {"kind": "webhook", "url": format!("{hook}/hook"), "template": "{\"text\":\"{{body}}\"}"}, "events": {"input": true, "finished": true, "failed": false}}),
        )
        .await;
    assert_eq!(saved.status(), 200);
    push_tx
        .send(json!({"type": "status", "session": "s1", "status": "error", "reason": null, "unread": false}))
        .unwrap();
    push_tx
        .send(json!({"type": "status", "session": "s1", "status": "needsYou", "reason": "answer", "unread": false}))
        .unwrap();
    let (_, body) = timeout(WAIT, hooks.recv()).await.unwrap().unwrap();
    assert_eq!(body, r#"{"text":"需要输入:Fix the build"}"#);

    let unpaired = s
        .call(
            "NotifyService/UnpairWatcher",
            Some(&first),
            json!({"computer": pc_id}),
        )
        .await;
    assert_eq!(unpaired.status(), 200);
    let listed: Value = s
        .call("NotifyService/ListWatchers", Some(&first), json!({}))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(listed["watchers"][0]["paired"], false);
}

/// The official Runner phone app, as captured against the official service:
/// a client enrollment without a host key, approved in the phone's browser,
/// then an `rcc_` credential for the computer list and the relay.
#[tokio::test]
async fn the_official_phone_app_enrolls_without_a_key() {
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let (pc_id, pc_cred) = s.enroll(&admin, "studio", 1).await;
    let (mut host, _) = s.host(&pc_cred).await;
    let request = json!({"kind": "ENROLLMENT_KIND_CLIENT", "client": {"platform": "ios", "runnerVersion": "0.1.0", "osVersion": "27.0", "name": "iPhone"}});
    let start: Value = s
        .call("HostEnrollmentService/StartEnrollment", None, request)
        .await
        .json()
        .await
        .unwrap();
    let code = start["userCode"]
        .as_str()
        .expect("enrollment starts")
        .to_owned();
    let poll = || async {
        s.call(
            "HostEnrollmentService/PollEnrollment",
            None,
            json!({"deviceCode": start["deviceCode"]}),
        )
        .await
        .json::<Value>()
        .await
        .unwrap()
    };
    assert_eq!(poll().await["state"], "ENROLLMENT_STATE_PENDING");
    // Nothing is approved until the person approves it.
    let page = admin
        .get(format!("{}/hosts/add?code={code}", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("批准这部手机"), "{page}");
    assert!(!page.contains("指纹"), "a keyless phone has no fingerprint");
    assert_eq!(poll().await["state"], "ENROLLMENT_STATE_PENDING");
    s.form(
        &admin,
        "/hosts/add",
        &[("code", &code), ("decision", "approve")],
    )
    .await;
    let issued = poll().await;
    assert_eq!(issued["state"], "ENROLLMENT_STATE_APPROVED");
    let credential = issued["credential"].as_str().unwrap().to_owned();
    assert!(credential.starts_with("rcc_"), "{credential}");
    assert_eq!(
        issued["relayUrl"],
        format!("{}/relay/client", s.origin.replacen("http", "ws", 1))
    );
    assert!(!issued["clientId"].as_str().unwrap().is_empty());
    assert_eq!(s.host_ids(&credential).await, vec![pc_id.clone()]);
    let _route = s
        .ws(
            &format!("/relay/client?host={pc_id}"),
            &credential,
            remote::CLIENT_SUBPROTOCOL,
        )
        .await
        .unwrap();
    assert_eq!(text(&mut host).await["type"], "channelOpen");

    // A second keyless phone does not replace the first.
    let again =
        json!({"kind": "ENROLLMENT_KIND_CLIENT", "client": {"platform": "ios", "name": "iPad"}});
    let start: Value = s
        .call("HostEnrollmentService/StartEnrollment", None, again)
        .await
        .json()
        .await
        .unwrap();
    s.form(
        &admin,
        "/hosts/add",
        &[
            ("code", start["userCode"].as_str().unwrap()),
            ("decision", "approve"),
        ],
    )
    .await;
    let second: Value = s
        .call(
            "HostEnrollmentService/PollEnrollment",
            None,
            json!({"deviceCode": start["deviceCode"]}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(second["state"], "ENROLLMENT_STATE_APPROVED");
    assert_eq!(
        s.host_ids(&credential).await,
        vec![pc_id],
        "the first phone still works"
    );
    // A computer still needs its key.
    let keyless = s
        .call(
            "HostEnrollmentService/StartEnrollment",
            None,
            json!({"host": {"hostname": "x"}}),
        )
        .await;
    assert_eq!(keyless.status(), 400);
}

#[tokio::test]
async fn phones_enroll_in_the_official_format_and_sign_out_as_clients() {
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let (pc_id, pc_cred) = s.enroll(&admin, "studio", 1).await;
    let (_host, _) = s.host(&pc_cred).await;
    let request = json!({
        "kind": "ENROLLMENT_KIND_CLIENT",
        "client": {"name": "Alice's iPhone", "platform": "ios", "osVersion": "26.1", "runnerVersion": "1.2.0"},
    });
    let (phone_id, phone_cred) = s.enroll_with(&admin, request, 4).await;
    assert_eq!(s.host_ids(&phone_cred).await, vec![pc_id.clone()]);
    assert_eq!(
        s.host_ids(&pc_cred).await,
        vec![pc_id.clone()],
        "not listed as a computer"
    );
    assert_eq!(
        refused_status(s.ws("/relay/host", &phone_cred, remote::SUBPROTOCOL).await),
        403
    );

    let wrong = s
        .call(
            "HostEnrollmentService/SignOutHost",
            Some(&phone_cred),
            json!({}),
        )
        .await;
    assert_eq!(wrong.status(), 401, "SignOutHost is a computer's");
    let denied = s
        .call(
            "HostEnrollmentService/SignOutClient",
            Some(&pc_cred),
            json!({}),
        )
        .await;
    assert_eq!(
        denied.status(),
        403,
        "a computer cannot sign out as a client"
    );
    let signed_out = s
        .call(
            "HostEnrollmentService/SignOutClient",
            Some(&phone_cred),
            json!({}),
        )
        .await;
    assert_eq!(signed_out.status(), 200);
    let after = s
        .call(
            "HostClientService/ListAccountHosts",
            Some(&phone_cred),
            json!({}),
        )
        .await;
    assert_eq!(after.status(), 401);
    assert!(s.host_ids(&pc_cred).await.contains(&pc_id));
    let _ = phone_id;
}

#[tokio::test]
async fn the_web_api_signs_in_and_manages_devices() {
    let s = server().await;
    s.setup(&browser()).await;
    let b = browser();

    let (status, body) = s.web(&b, "AccountService/GetMe", json!({})).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (401, Some("unauthenticated"))
    );
    assert!(body.get("serverVersion").is_none());
    let (status, body) = s
        .web(
            &b,
            "AuthService/SignIn",
            json!({"username": "alice", "password": "wrong-password"}),
        )
        .await;
    assert_eq!(status, 401);
    assert_eq!(body["details"][0]["type"], "runner_server.v1.ErrorDetail");
    assert_eq!(
        body["details"][0]["value"], "CAE",
        "ERROR_CODE_INVALID_CREDENTIALS"
    );
    let (status, body) = s
        .web(
            &b,
            "AuthService/SignIn",
            json!({"username": "alice", "password": "correct-horse", "captchaId": "", "captchaAnswer": ""}),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user"]["username"], "alice");
    assert_eq!(body["user"]["isAdmin"], true);
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(body["serverVersion"], version, "told once signed in");
    let (status, me) = s.web(&b, "AccountService/GetMe", json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(me["user"]["id"], body["user"]["id"]);
    assert_eq!(me["serverVersion"], version);

    for method in ["AuthService/GetCaptcha", "AuthService/Register"] {
        assert_eq!(s.web(&b, method, json!({})).await.0, 501, "{method}");
    }
    let foreign = b
        .post(format!(
            "{}/api/runner_server.v1.HostService/ListHosts",
            s.origin
        ))
        .header("Origin", "https://evil.example")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), 403, "cross-origin calls are rejected");
    let form = b
        .post(format!(
            "{}/api/runner_server.v1.HostService/ListHosts",
            s.origin
        ))
        .form(&[("a", "b")])
        .send()
        .await
        .unwrap();
    assert_eq!(form.status(), 400, "only JSON bodies");

    // A phone signs in in the official format and is approved through the API.
    let start: Value = s
        .rpc
        .post(format!(
            "{}/api/runner_server.v1.HostEnrollmentService/StartEnrollment",
            s.origin
        ))
        .header("X-Forwarded-For", "198.51.100.1, 203.0.113.9")
        .json(&json!({
            "kind": "ENROLLMENT_KIND_CLIENT",
            "client": {"name": "iPhone 17", "platform": "ios", "osVersion": "26.1", "runnerVersion": "1.2.0"},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_code = start["userCode"].as_str().unwrap().to_lowercase();
    let (status, found) = s
        .web(
            &b,
            "HostService/LookupEnrollment",
            json!({"userCode": user_code}),
        )
        .await;
    assert_eq!(status, 200, "{found}");
    let e = &found["enrollment"];
    assert_eq!(e["kind"], "ENROLLMENT_KIND_CLIENT");
    assert_eq!(e["client"]["name"], "iPhone 17");
    assert_eq!(e["client"]["osVersion"], "26.1");
    assert_eq!(e["requestingIp"], "203.0.113.9");
    assert!(
        e["fingerprint"].as_str().unwrap_or_default().is_empty(),
        "a phone has no key"
    );
    assert_eq!(
        s.web(
            &b,
            "HostService/LookupEnrollment",
            json!({"userCode": "BCDF-GHJK"})
        )
        .await
        .0,
        404
    );
    let (status, _) = s
        .web(
            &b,
            "HostService/ApproveEnrollment",
            json!({"userCode": user_code, "name": "Work phone"}),
        )
        .await;
    assert_eq!(status, 200);
    let poll: PollResponse = s
        .call(
            "HostEnrollmentService/PollEnrollment",
            None,
            json!({"deviceCode": start["deviceCode"]}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(poll.state, EnrollmentState::Approved);
    assert!(poll.host_id.is_empty(), "phones get a clientId instead");
    let (phone_id, phone_cred) = (poll.client_id, poll.credential.0);

    let (pc_id, pc_cred) = s.enroll(&b, "studio", 1).await;
    let (_, hosts) = s.web(&b, "HostService/ListHosts", json!({})).await;
    assert!(
        hosts["hosts"].as_array().unwrap().is_empty(),
        "listed once connected"
    );
    let (mut host, _) = s.host(&pc_cred).await;
    let (_, hosts) = s.web(&b, "HostService/ListHosts", json!({})).await;
    assert_eq!(hosts["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(hosts["hosts"][0]["id"], pc_id);
    assert_eq!(hosts["hosts"][0]["online"], true);
    let (_, clients) = s.web(&b, "HostService/ListClients", json!({})).await;
    assert_eq!(clients["clients"][0]["id"], phone_id);
    assert_eq!(
        clients["clients"][0]["name"], "Work phone",
        "named on approval"
    );
    assert_eq!(clients["clients"][0]["info"]["name"], "iPhone 17");

    let mut route = s
        .ws(
            &format!("/relay/client?host={pc_id}"),
            &phone_cred,
            remote::CLIENT_SUBPROTOCOL,
        )
        .await
        .unwrap();
    let open = text(&mut host).await;
    assert_eq!(open["device"]["kind"], "phone");
    let (_, connections) = s.web(&b, "HostService/ListConnections", json!({})).await;
    let c = &connections["connections"].as_array().unwrap()[..];
    assert_eq!(c.len(), 1, "{connections}");
    assert_eq!(c[0]["host"]["id"], pc_id);
    assert_eq!(c[0]["host"]["online"], true);
    assert_eq!(c[0]["phone"]["id"], phone_id);
    assert!(c[0].get("computer").is_none());

    let (status, _) = s
        .web(
            &b,
            "HostService/RenameHost",
            json!({"hostId": pc_id, "name": "desk"}),
        )
        .await;
    assert_eq!(status, 200);
    let (_, hosts) = s.web(&b, "HostService/ListHosts", json!({})).await;
    assert_eq!(hosts["hosts"][0]["name"], "desk");
    assert_eq!(
        s.web(&b, "HostService/RemoveHost", json!({"hostId": phone_id}))
            .await
            .0,
        404,
        "RemoveHost does not remove phones"
    );
    let (status, _) = s
        .web(
            &b,
            "HostService/RemoveClient",
            json!({"clientId": phone_id}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        close_code(&mut route).await,
        4003,
        "the phone's route closes"
    );
    let closed = text(&mut host).await;
    assert_eq!(closed["type"], "channelClosed");
    let (_, connections) = s.web(&b, "HostService/ListConnections", json!({})).await;
    assert!(connections["connections"].as_array().unwrap().is_empty());

    let refreshed = b
        .post(format!(
            "{}/api/runner_server.v1.AuthService/Refresh",
            s.origin
        ))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(refreshed.status(), 200);
    assert!(refreshed.headers().contains_key("set-cookie"));
    assert_eq!(s.web(&b, "AuthService/SignOut", json!({})).await.0, 200);
    assert_eq!(s.web(&b, "AccountService/GetMe", json!({})).await.0, 401);
    assert_eq!(s.web(&b, "AuthService/Refresh", json!({})).await.0, 401);
}

#[tokio::test]
async fn admins_manage_accounts_through_the_web_api() {
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let (_, me) = s.web(&admin, "AccountService/GetMe", json!({})).await;
    let alice = me["user"]["id"].as_str().unwrap().to_owned();

    let bob_password = "bob-password";
    let (status, created) = s
        .web(
            &admin,
            "AdminService/CreateUser",
            json!({"username": "bob", "displayName": "Bob", "password": bob_password}),
        )
        .await;
    assert_eq!(status, 200, "{created}");
    let bob = created["user"]["id"].as_str().unwrap().to_owned();
    let (status, taken) = s
        .web(
            &admin,
            "AdminService/CreateUser",
            json!({"username": "BOB", "password": bob_password}),
        )
        .await;
    assert_eq!(
        (status, taken["code"].as_str()),
        (409, Some("already_exists"))
    );
    assert_eq!(
        s.web(
            &admin,
            "AdminService/CreateUser",
            json!({"username": "carol", "password": "short"})
        )
        .await
        .0,
        400
    );

    let b = browser();
    let sign_in = |password: &'static str| {
        let (s, b) = (&s, &b);
        async move {
            s.web(
                b,
                "AuthService/SignIn",
                json!({"username": "bob", "password": password}),
            )
            .await
        }
    };
    assert_eq!(sign_in(bob_password).await.0, 200);
    let (status, body) = s.web(&b, "AdminService/ListUsers", json!({})).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_denied"))
    );

    let (_, users) = s.web(&admin, "AdminService/ListUsers", json!({})).await;
    let users = users["users"].as_array().unwrap().clone();
    assert_eq!(users.len(), 2);
    let row = users
        .iter()
        .find(|u| u["user"]["id"] == bob.as_str())
        .unwrap();
    assert_eq!(row["status"], "USER_STATUS_ACTIVE");
    assert!(row["lastLoginAt"].is_string(), "{row}");

    let (status, body) = s
        .web(
            &admin,
            "AdminService/DeactivateUser",
            json!({"userId": alice}),
        )
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (400, Some("failed_precondition"))
    );

    let (status, reset) = s
        .web(&admin, "AdminService/ResetPassword", json!({"userId": bob}))
        .await;
    assert_eq!(status, 200);
    let temporary = reset["temporaryPassword"].as_str().unwrap().to_owned();
    assert_eq!(
        s.web(&b, "AccountService/GetMe", json!({})).await.0,
        401,
        "signed out"
    );
    let temporary: &'static str = Box::leak(temporary.into_boxed_str());
    assert_eq!(sign_in(temporary).await.0, 200);
    let (status, _) = s
        .web(
            &b,
            "AccountService/ChangePassword",
            json!({"currentPassword": temporary, "newPassword": bob_password}),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        s.web(&b, "AccountService/GetMe", json!({})).await.0,
        200,
        "keeps this session"
    );

    assert_eq!(
        s.web(
            &admin,
            "AdminService/DeactivateUser",
            json!({"userId": bob})
        )
        .await
        .0,
        200
    );
    assert_eq!(s.web(&b, "AccountService/GetMe", json!({})).await.0, 401);
    let (status, body) = sign_in(bob_password).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (403, Some("permission_denied"))
    );
    assert_eq!(
        s.web(
            &admin,
            "AdminService/ReactivateUser",
            json!({"userId": bob})
        )
        .await
        .0,
        200
    );
    assert_eq!(sign_in(bob_password).await.0, 200);

    assert_eq!(
        s.web(
            &admin,
            "AdminService/SetAdmin",
            json!({"userId": bob, "isAdmin": true})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        s.web(&b, "AdminService/ListUsers", json!({})).await.0,
        200,
        "bob is an admin"
    );
    assert_eq!(
        s.web(&admin, "AdminService/DeleteUser", json!({"userId": bob}))
            .await
            .0,
        200
    );
    let (_, users) = s.web(&admin, "AdminService/ListUsers", json!({})).await;
    assert_eq!(users["users"].as_array().unwrap().len(), 1);
    assert_eq!(
        s.web(&admin, "AdminService/DeleteUser", json!({"userId": bob}))
            .await
            .0,
        404
    );
    assert_eq!(
        s.web(&admin, "AdminService/CreateInvite", json!({}))
            .await
            .0,
        501
    );
}

#[tokio::test]
async fn the_approval_page_names_the_device() {
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let start: StartResponse = s
        .call(
            "HostEnrollmentService/StartEnrollment",
            None,
            json!({"host": {"hostname": "localhost"}, "hostKey": STANDARD.encode([6; 32])}),
        )
        .await
        .json()
        .await
        .unwrap();
    let page = admin
        .get(&start.verification_uri_complete)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(r#"name="name" value="localhost""#), "{page}");
    let approved = s
        .form(
            &admin,
            "/hosts/add",
            &[
                ("code", &start.user_code),
                ("decision", "approve"),
                ("name", " Desk "),
            ],
        )
        .await;
    assert!(approved.text().await.unwrap().contains("已批准"));
    let poll: PollResponse = s
        .call(
            "HostEnrollmentService/PollEnrollment",
            None,
            json!({"deviceCode": start.device_code.0}),
        )
        .await
        .json()
        .await
        .unwrap();
    let (_socket, welcome) = s.host(&poll.credential.0).await;
    assert_eq!(welcome["name"], "Desk");
}

#[tokio::test]
async fn the_approval_page_returns_to_the_phone_app() {
    let s = server().await;
    let jar = std::sync::Arc::new(reqwest::cookie::Jar::default());
    let admin = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .build()
        .unwrap();
    s.setup(&admin).await;
    // The app's sign-in browser stops at the redirect back to the app.
    let app_browser = reqwest::Client::builder()
        .cookie_provider(jar)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let start: StartResponse = s
        .call(
            "HostEnrollmentService/StartEnrollment",
            None,
            json!({
                "kind": "ENROLLMENT_KIND_CLIENT",
                "client": {"name": "Pixel"},
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    let page = app_browser
        .get(format!("{}&app=1", start.verification_uri_complete))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains(r#"name="app" value="1""#), "{page}");
    let decided = s
        .form(
            &app_browser,
            "/hosts/add",
            &[
                ("code", &start.user_code),
                ("decision", "approve"),
                ("app", "1"),
            ],
        )
        .await;
    assert_eq!(decided.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(
        decided.headers()["location"],
        "runner-remote-auth://enrollment?result=approved"
    );
    let poll: PollResponse = s
        .call(
            "HostEnrollmentService/PollEnrollment",
            None,
            json!({"deviceCode": start.device_code.0}),
        )
        .await
        .json()
        .await
        .unwrap();
    assert!(!poll.credential.0.is_empty());

    // Opened in an ordinary browser, the page keeps no way back to the app.
    let page = admin
        .get(format!("{}/hosts/add?code=ABCD-EFGH", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains(r#"name="app""#));
}

#[tokio::test]
async fn device_management_lists_phones_apart_and_takes_the_code_in_boxes() {
    let s = server().await;
    let admin = browser();
    s.setup(&admin).await;
    let start: StartResponse = s
        .call(
            "HostEnrollmentService/StartEnrollment",
            None,
            json!({
                "kind": "ENROLLMENT_KIND_CLIENT",
                "client": {"name": "Pixel 9", "platform": "android"},
            }),
        )
        .await
        .json()
        .await
        .unwrap();
    // Lower case and no dash are accepted.
    let code = start.user_code.replace('-', "").to_lowercase();
    let page = admin
        .get(format!("{}/hosts/add?code={code}", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("批准这部手机"), "{page}");
    s.form(
        &admin,
        "/hosts/add",
        &[("code", &start.user_code), ("decision", "approve")],
    )
    .await;
    // The phone is added once it collects its credential.
    s.call(
        "HostEnrollmentService/PollEnrollment",
        None,
        json!({"deviceCode": start.device_code.0}),
    )
    .await;

    let hosts = admin
        .get(format!("{}/hosts", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(hosts.contains("<h1>设备管理</h1>"), "{hosts}");
    let (computers, phones) = hosts
        .split_once("<h2 style=\"margin-top:24px\">手机</h2>")
        .unwrap();
    assert!(computers.contains("还没有电脑"));
    assert!(phones.contains("Pixel 9"));

    let form = admin
        .get(format!("{}/hosts/add", s.origin))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(form.contains("<h1>添加设备</h1>"));
    assert_eq!(form.matches(r#"class="box""#).count(), 8);
    assert!(form.contains(r#"<span class="dash">-</span>"#));
}
