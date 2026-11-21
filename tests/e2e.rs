use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use runner_core::{
    companion::channel,
    remote::{self, EnrollmentState, PollResponse, StartResponse},
};
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
        let start: StartResponse = self
            .call(
                "HostEnrollmentService/StartEnrollment",
                None,
                json!({
                    "host": {"hostname": name, "platform": "linux", "arch": "x86_64", "osVersion": "Test", "runnerVersion": "0.20.2"},
                    "hostKey": STANDARD.encode([key; 32]),
                }),
            )
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
        assert!(
            page.contains(&remote::fingerprint(&[key; 32])),
            "approval page shows the fingerprint"
        );
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
        assert!(remote::valid_credential(&issued.credential.0));
        assert!(remote::valid_relay_url(&self.origin, &issued.relay_url));
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
        (issued.host_id.clone(), issued.credential.0.clone())
    }

    async fn ws(
        &self,
        path: &str,
        credential: &str,
        protocol: &str,
    ) -> Result<Ws, tungstenite::Error> {
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
        let (socket, response) = connect_async(request).await?;
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

fn refused_status(result: Result<Ws, tungstenite::Error>) -> u16 {
    match result {
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
    let mut client = s.ws(&route, &b_cred, "runner-client.v1").await.unwrap();
    let open = text(&mut host_a).await;
    assert_eq!(open["type"], "channelOpen");
    let ch = open["channel"].as_u64().unwrap() as u32;
    client
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(binary(&mut host_a).await, channel::wrap(ch, &[1, 2, 3]));
    host_a
        .send(Message::Binary(channel::wrap(ch, &[9, 9]).into()))
        .await
        .unwrap();
    assert_eq!(binary(&mut client).await, vec![9, 9]);

    let closing = json!({"type": "closeChannel", "channel": ch});
    host_a
        .send(Message::Text(closing.to_string().into()))
        .await
        .unwrap();
    assert_eq!(close_code(&mut client).await, 1000);

    let mut second = s.ws(&route, &b_cred, "runner-client.v1").await.unwrap();
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
        refused_status(s.ws(&route, &c_cred, "runner-client.v1").await),
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
