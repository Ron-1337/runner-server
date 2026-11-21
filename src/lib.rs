pub mod auth;
pub mod config;
pub mod db;
pub mod html;
pub mod relay;
pub mod rpc;
pub mod web;

use axum::Router;
use std::{ops::Deref, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

pub struct Inner {
    pub config: config::Config,
    pub db: db::Db,
    pub hub: relay::Hub,
    pub limiter: auth::LoginLimiter,
}

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(config: config::Config, db: db::Db) -> Self {
        Self(Arc::new(Inner {
            config,
            db,
            hub: relay::Hub::default(),
            limiter: auth::LoginLimiter::default(),
        }))
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .merge(rpc::routes())
        .merge(relay::routes())
        .merge(web::routes(state.clone()))
        .with_state(state)
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn spawn_maintenance(state: AppState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        loop {
            tick.tick().await;
            let now = now();
            if let Err(e) = state.db.call(move |c| db::purge(c, now)).await {
                tracing::warn!("maintenance failed: {e:#}");
            }
        }
    });
}
