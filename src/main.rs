mod api;
mod config;
mod dns;
mod failover;
mod health;

use futures::future::join_all;
use std::{process, time::Duration};
use tokio::time::{MissedTickBehavior, interval};

use failover::{FailoverTrigger, dns_trigger};

use health::HealthCheckError;

#[tokio::main]
async fn main() {
    let config_path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let config = match config::load(&config_path) {
        Ok(servers) => servers,
        Err(error) => {
            eprintln!(
                "設定ファイル {}: {error}",
                std::path::Path::new(&config_path).display()
            );
            process::exit(1);
        }
    };

    let config::Config {
        monitor,
        dns_servers,
        mut adguard_servers,
    } = config;
    let config::MonitorConfig {
        adguard_health_check_mode,
        adguard_health_check,
        retry,
        timeout_sec,
        interval_sec,
        query_fqdn,
    } = monitor;
    let mut servers: Vec<_> = dns_servers
        .into_iter()
        .map(config::DnsConfig::into_server)
        .collect();
    // 起動時の上流設定を取得し、すでに目的の設定なら重複更新を避ける。
    // 稼働中の外部変更はここでは追跡せず、取得失敗時は Unknown のまま監視を開始する。
    for adg in &mut adguard_servers {
        match adg.get_upstreams().await {
            Ok(upstreams) => {
                adg.active_dns = adg.classify_upstreams(&upstreams);
                match adg.active_dns {
                    api::ActiveDns::Primary => println!("{}: Primary DNSを使用中", adg.name),
                    api::ActiveDns::Fallback => println!("{}: Fallback DNSを使用中", adg.name),
                    api::ActiveDns::Unknown => eprintln!(
                        "{}: 上流 DNS が Primary / Fallback の設定と一致しません (Unknown)",
                        adg.name
                    ),
                }
            }
            Err(e) => {
                eprintln!("{}: {}", adg.name, e.to_string());
            }
        }
    }

    // 初回 tick は即時実行。処理が遅れた場合は、過去の tick をまとめて消化せず飛ばす。
    let mut ticker = interval(Duration::from_secs(interval_sec));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        // 次のヘルスチェック時刻まで待機
        ticker.tick().await;

        if adguard_health_check {
            // AdGuard 本体の状態は記録・表示用で、上流 DNS の切り替え条件には使わない。
            let results = join_all(adguard_servers.iter_mut().map(|server| {
                server.check_health(
                    adguard_health_check_mode,
                    &query_fqdn,
                    Duration::from_secs(timeout_sec),
                    retry,
                )
            }))
            .await;
            for (server, result) in adguard_servers.iter().zip(results) {
                match result {
                    Ok(()) => println!(
                        "{} AdGuard OK (state: {:?})",
                        server.name, server.monitor.state
                    ),
                    Err(error) => eprintln!(
                        "{} AdGuard Error: {:?} (state: {:?}, failures: {}/{})",
                        server.name,
                        error,
                        server.monitor.state,
                        server.monitor.consecutive_failed,
                        retry
                    ),
                }
            }
        }

        for server in &servers {
            println!(
                "{} health monitor challenge {}/{}",
                server.name,
                server.monitor.consecutive_failed + 1,
                retry
            );
        }

        // 全サーバーを並列にチェックし、各サーバーの監視状態を更新
        let results = join_all(servers.iter_mut().map(|server| {
            server.health_check(&query_fqdn, Duration::from_secs(timeout_sec), retry)
        }))
        .await;

        // 今回の成否を表示する。切り替え判定には retry を反映した監視状態を使う。
        for (server, result) in servers.iter().zip(results) {
            match result {
                Ok(()) => println!("{} DNS OK", server.name),
                Err(HealthCheckError::Dns(error)) => {
                    println!("{} DNS Error: {error}", server.name);
                }
                Err(HealthCheckError::Api(error)) => {
                    eprintln!("{} API Error: {error}", server.name);
                }
                Err(HealthCheckError::Timeout) => {
                    println!("{} DNS Timeout", server.name);
                }
            }
        }

        // Primary 全台 Down かつ Fallback に Up があれば切り替え、Primary 全台 Up で復帰。
        // Fallback 未登録・正常未確認の場合は切り替えない。
        for state_group in [api::ActiveDns::Primary, api::ActiveDns::Fallback] {
            let dns_group = servers
                .iter()
                .filter(|server| server.state_group == state_group);

            if state_group != api::ActiveDns::Primary {
                continue;
            }

            let trigger = dns_trigger(
                dns_group.map(|server| server.monitor.state),
                servers
                    .iter()
                    .filter(|server| server.state_group == api::ActiveDns::Fallback)
                    .map(|server| server.monitor.state),
            );

            if trigger == FailoverTrigger::NoHealthyFallback {
                eprintln!(
                    "Primary が全台 Down ですが、正常な Fallback が確認できないため切り替えを見送ります"
                );
                continue;
            }

            // Trigger対象外であれば再ループ
            if trigger == FailoverTrigger::NoTrigger {
                continue;
            }

            // 内部状態が切り替え先と異なる AdGuard にだけ設定を反映する。
            for adg in &mut adguard_servers {
                match trigger {
                    FailoverTrigger::PrimaryToFallback
                        if adg.active_dns != api::ActiveDns::Fallback =>
                    {
                        adg.failover().await
                    }
                    FailoverTrigger::FallbackToPrimary
                        if adg.active_dns != api::ActiveDns::Primary =>
                    {
                        adg.failback().await
                    }
                    _ => {}
                }
            }
        }
    }
}
