use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use runner_server::{AppState, app, auth, config::Config, db};
use std::{io::BufRead, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "Self-hosted account service and relay for Runner remote access"
)]
struct Cli {
    /// SQLite database file.
    #[arg(
        long,
        env = "RUNNER_SERVER_DB",
        default_value = "runner-server.db",
        global = true
    )]
    db: PathBuf,
    /// Address to listen on; put a TLS reverse proxy in front of it.
    #[arg(long, env = "RUNNER_SERVER_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Public origin users and Runner reach, such as https://runner.example.com.
    #[arg(
        long,
        env = "RUNNER_SERVER_ORIGIN",
        default_value = "http://localhost:8080"
    )]
    origin: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Set a user's password, creating the user if missing; reads the password from stdin.
    SetPassword {
        username: String,
        /// Also make the user a system administrator and re-enable it.
        #[arg(long)]
        admin: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let db = db::Db::open(&cli.db).with_context(|| format!("open {}", cli.db.display()))?;
    if let Some(Command::SetPassword { username, admin }) = cli.command {
        return set_password(&db, &username, admin);
    }

    let config = Config::new(&cli.origin)?;
    let state = AppState::new(config, db);
    runner_server::spawn_maintenance(state.clone());
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("bind {}", cli.listen))?;
    tracing::info!("listening on {} for {}", cli.listen, state.config.origin);
    let hub = state.clone();
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            hub.hub.shutdown();
        })
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn set_password(db: &db::Db, username: &str, admin: bool) -> anyhow::Result<()> {
    auth::validate_username(username).map_err(|m| anyhow::anyhow!(m))?;
    eprintln!("New password for {username}:");
    let mut password = String::new();
    std::io::stdin().lock().read_line(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']);
    auth::validate_password(password, password).map_err(|m| anyhow::anyhow!(m))?;
    let hash = auth::hash_password(password)?;
    let conn = db.lock();
    match db::user_with_hash(&conn, username)? {
        Some((user, _)) => {
            db::set_password(&conn, user.id, &hash)?;
            db::delete_sessions(&conn, user.id, None)?;
            if admin {
                db::set_admin(&conn, user.id, true)?;
                db::set_disabled(&conn, user.id, false)?;
            }
            eprintln!("Password updated for {}.", user.username);
        }
        None => {
            let now = runner_server::now();
            if db::insert_user(&conn, username, username, &hash, admin, now)?.is_none() {
                bail!("could not create {username}");
            }
            eprintln!(
                "Created {username}{}.",
                if admin { " as administrator" } else { "" }
            );
        }
    }
    Ok(())
}
