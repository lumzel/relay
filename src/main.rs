#[tokio::main]
async fn main() {
    let cli = match lumzel_relay::CliArgs::parse(std::env::args().skip(1)) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("lumzel-relay: {err}\n\n{}", lumzel_relay::CliArgs::usage());
            std::process::exit(2);
        }
    };
    if cli.help {
        print!("{}", lumzel_relay::CliArgs::usage());
        return;
    }

    let bind = cli
        .bind
        .or_else(|| std::env::var("RELAY_BIND").ok())
        .unwrap_or_else(|| "0.0.0.0:8080".into());

    let mut state = lumzel_relay::AppState::from_env();
    if let Some(password) = cli.password {
        state = state.with_password(password);
    }

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("lumzel-relay: bind {bind}: {err}");
            std::process::exit(1);
        }
    };
    let auth_mode = if state.is_password_protected() {
        "password"
    } else {
        "open"
    };
    eprintln!("lumzel-relay listening on {bind} (auth: {auth_mode})");

    let stun_cfg = cli
        .stun_bind
        .or_else(|| std::env::var("RELAY_STUN_BIND").ok());
    let _stun = if let Some(stun_env) = stun_cfg {
        let addrs = lumzel_relay::parse_bind_addrs(&stun_env);
        if !addrs.is_empty() {
            match lumzel_relay::StunServer::start(&addrs, lumzel_relay::stun::DEFAULT_RATE_LIMIT)
                .await
            {
                Ok(srv) => {
                    eprintln!("lumzel-relay STUN listening on {:?}", srv.addrs);
                    Some(srv)
                }
                Err(err) => {
                    eprintln!("lumzel-relay: stun bind error: {err}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Err(err) = lumzel_relay::serve(listener, state).await {
        eprintln!("lumzel-relay: {err}");
        std::process::exit(1);
    }
}
