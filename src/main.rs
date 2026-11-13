#[tokio::main]
async fn main() {
    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("lumzel-relay: bind {bind}: {err}");
            std::process::exit(1);
        }
    };
    eprintln!("lumzel-relay listening on {bind}");

    let _stun = if let Ok(stun_env) = std::env::var("RELAY_STUN_BIND") {
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

    if let Err(err) = lumzel_relay::serve(listener, lumzel_relay::AppState::from_env()).await {
        eprintln!("lumzel-relay: {err}");
        std::process::exit(1);
    }
}
