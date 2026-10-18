use hickory_resolver::{
    Resolver, TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RecordType,
};
use std::{net::IpAddr, time::Duration};
use tokio::time::timeout;

use crate::{
    api,
    health::{HealthCheckError, HealthMonitor},
};

pub(crate) enum DNSServerType {
    Tcp,
    Udp,
    DoH {
        server_name: String,
        path: String,
        port: u16,
    },
}

pub(crate) struct DnsServer {
    pub(crate) name: String,
    pub(crate) state_group: api::ActiveDns,
    resolver: TokioResolver,
    pub(crate) monitor: HealthMonitor,
}

impl DnsServer {
    pub(crate) fn new(
        name: impl Into<String>,
        state_group: api::ActiveDns,
        server_ip: IpAddr,
        server_type: DNSServerType,
    ) -> Self {
        Self {
            name: name.into(),
            state_group: state_group,
            resolver: resolver_builder(server_ip, server_type),
            monitor: HealthMonitor::new(),
        }
    }

    pub(crate) async fn health_check(
        &mut self,
        query_fqdn: &str,
        timeout_duration: Duration,
        retry: u32,
    ) -> Result<(), HealthCheckError> {
        let result = self.check_once(query_fqdn, timeout_duration).await;
        let previous = self.monitor.state;
        self.monitor.record_with_retry(&result, retry);
        self.monitor
            .log_transition(previous, &self.name, "DNS", &result);
        result
    }

    // AdGuard 本体の監視では、呼び出し側が状態とログを管理する。
    pub(crate) async fn check_once(
        &self,
        query_fqdn: &str,
        timeout_duration: Duration,
    ) -> Result<(), HealthCheckError> {
        health_check(&self.resolver, query_fqdn, timeout_duration).await
    }
}

fn resolver_builder(server_ip: IpAddr, dns_server_type: DNSServerType) -> TokioResolver {
    let name_server = name_server_config(server_ip, dns_server_type);
    let config = ResolverConfig::from_name_servers(vec![name_server]);

    let mut options = ResolverOpts::default();
    // 監視のたびに問い合わせ、ローカルキャッシュで障害が隠れることを防ぐ。
    options.cache_size = 0;

    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .unwrap()
}

fn name_server_config(server_ip: IpAddr, dns_server_type: DNSServerType) -> NameServerConfig {
    match dns_server_type {
        DNSServerType::Tcp => NameServerConfig::tcp(server_ip),

        DNSServerType::Udp => NameServerConfig::udp(server_ip),

        DNSServerType::DoH {
            server_name,
            path,
            port,
        } => {
            let mut config =
                NameServerConfig::https(server_ip, server_name.into(), Some(path.into()));
            config.connections[0].port = port;
            config
        }
    }
}

async fn health_check(
    resolver: &TokioResolver,
    query_fqdn: &str,
    timeout_duration: Duration,
) -> Result<(), HealthCheckError> {
    match timeout(timeout_duration, resolver.lookup(query_fqdn, RecordType::A)).await {
        Ok(Ok(_response)) => Ok(()),

        Ok(Err(error)) => Err(HealthCheckError::Dns(error.to_string())),

        Err(_) => Err(HealthCheckError::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::ProtocolConfig;

    #[tokio::test]
    async fn dns_failures_wait_for_retry_threshold() {
        use crate::health::HealthCheckState;

        let mut server = DnsServer::new(
            "test",
            api::ActiveDns::Primary,
            "127.0.0.1".parse().unwrap(),
            DNSServerType::Udp,
        );
        // 不正な問い合わせ名で、外部通信せず失敗経路を確認する。
        for attempt in 1..=3 {
            assert!(
                server
                    .health_check("bad..name", Duration::from_secs(1), 3)
                    .await
                    .is_err()
            );
            assert_eq!(server.monitor.consecutive_failed, attempt);
            assert_eq!(
                server.monitor.state,
                if attempt < 3 {
                    HealthCheckState::Unknown
                } else {
                    HealthCheckState::Down
                }
            );
        }
        server.monitor.record_with_retry(&Ok(()), 3);
        assert_eq!(server.monitor.state, HealthCheckState::Up);
        assert_eq!(server.monitor.consecutive_failed, 0);
        assert!(
            server
                .health_check("bad..name", Duration::from_secs(1), 3)
                .await
                .is_err()
        );
        assert_eq!(server.monitor.state, HealthCheckState::Up);
        assert_eq!(server.monitor.consecutive_failed, 1);
    }

    #[tokio::test]
    async fn builds_doh_with_tls_name_path_and_port() {
        let server_type = || DNSServerType::DoH {
            server_name: "dns.example.com".into(),
            path: "/custom-query".into(),
            port: 8443,
        };
        let ip = "127.0.0.1".parse().unwrap();
        let config = name_server_config(ip, server_type());
        assert_eq!(config.ip, ip);
        assert_eq!(config.connections.len(), 1);
        assert_eq!(config.connections[0].port, 8443);
        match &config.connections[0].protocol {
            ProtocolConfig::Https { server_name, path } => {
                assert_eq!(&**server_name, "dns.example.com");
                assert_eq!(&**path, "/custom-query");
            }
            other => panic!("Unexpected protocol: {other:?}"),
        }
        let _resolver = resolver_builder(ip, server_type());
    }
}
