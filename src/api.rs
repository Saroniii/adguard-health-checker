use crate::health::{HealthCheckError, HealthMonitor};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct AdGuardClient {
    api_timeout: Duration,
    pub(crate) monitor: HealthMonitor,
    pub client: Client,
    pub name: String,
    pub base_url: String,
    pub active_upstreams: Vec<String>,
    pub standby_upstreams: Vec<String>,
    // 起動時の取得結果と切り替え成功時に更新する、上流 DNS の内部状態。
    pub active_dns: ActiveDns,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveDns {
    Primary,
    Fallback,
    Unknown,
}

impl AdGuardClient {
    /// 上流の並び順を無視して設定と照合し、一致しなければ Unknown を返す。
    pub(crate) fn classify_upstreams(&self, upstreams: &[String]) -> ActiveDns {
        fn same_upstreams(left: &[String], right: &[String]) -> bool {
            let mut left: Vec<_> = left.iter().collect();
            let mut right: Vec<_> = right.iter().collect();
            left.sort_unstable();
            right.sort_unstable();
            left == right
        }
        if same_upstreams(upstreams, &self.active_upstreams) {
            ActiveDns::Primary
        } else if same_upstreams(upstreams, &self.standby_upstreams) {
            ActiveDns::Fallback
        } else {
            ActiveDns::Unknown
        }
    }

    pub(crate) async fn check_health(
        &mut self,
        mode: crate::config::AdGuardHealthCheckMode,
        query_fqdn: &str,
        timeout: Duration,
        retry: u32,
    ) -> Result<(), HealthCheckError> {
        if mode == crate::config::AdGuardHealthCheckMode::Control {
            return self.health_check(self.api_timeout, retry).await;
        }

        // DNS 方式では管理画面のポートを使わず、同じホストの UDP/53 を確認する。
        // ホスト名の解決も含めて、監視全体を指定時間内に制限する。
        let result = tokio::time::timeout(timeout, async {
            let url = reqwest::Url::parse(&self.base_url)
                .map_err(|_| HealthCheckError::Dns("Invalid AdGuard URL".into()))?;
            let host = url
                .host_str()
                .ok_or_else(|| HealthCheckError::Dns("Missing AdGuard host".into()))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                ip
            } else {
                tokio::net::lookup_host((host, 53))
                    .await
                    .map_err(|_| HealthCheckError::Dns("Cannot resolve AdGuard host".into()))?
                    .next()
                    .ok_or_else(|| HealthCheckError::Dns("No address for AdGuard host".into()))?
                    .ip()
            };
            let mut server = crate::dns::DnsServer::new(
                &self.name,
                ActiveDns::Unknown,
                ip,
                crate::dns::DNSServerType::Udp,
            );
            server.health_check(query_fqdn, timeout, retry).await
        })
        .await
        .unwrap_or(Err(HealthCheckError::Timeout));
        // 一時生成した DNS サーバーではなく、クライアント側で連続失敗を保持する。
        self.monitor.record_with_retry(&result, retry);
        result
    }

    pub fn new(
        name: String,
        base_url: String,
        active_upstreams: Vec<String>,
        standby_upstreams: Vec<String>,
        username: String,
        password: String,
    ) -> Self {
        Self {
            api_timeout: Duration::from_secs(5),
            monitor: HealthMonitor::new(),
            client: Client::new(),
            name,
            base_url,
            active_upstreams,
            standby_upstreams,
            active_dns: ActiveDns::Unknown,
            username,
            password,
        }
    }

    pub fn with_api_timeout(mut self, timeout: Duration) -> Self {
        self.api_timeout = timeout;
        self
    }

    // Control 方式は HTTP 成功だけでなく、running = true を正常とする。
    pub(crate) async fn health_check(
        &mut self,
        timeout: Duration,
        retry: u32,
    ) -> Result<(), HealthCheckError> {
        let result = match tokio::time::timeout(timeout, async {
            let status = self
                .client
                .get(format!("{}/control/status", self.base_url))
                .timeout(self.api_timeout)
                .basic_auth(&self.username, Some(&self.password))
                .send()
                .await?
                .error_for_status()?
                .json::<ServerStatus>()
                .await?;
            Ok::<_, reqwest::Error>(status.running)
        })
        .await
        {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err(HealthCheckError::Api(
                "AdGuard DNS server is not running".into(),
            )),
            Ok(Err(error)) if error.is_timeout() => Err(HealthCheckError::Timeout),
            Ok(Err(error)) => Err(HealthCheckError::Api(error.without_url().to_string())),
            Err(_) => Err(HealthCheckError::Timeout),
        };
        self.monitor.record_with_retry(&result, retry);
        result
    }

    /// 上流 DNS のみを更新する。内部状態の更新とキャッシュ削除は呼び出し側で行う。
    pub async fn set_upstreams(&self, upstreams: &[String]) -> Result<(), reqwest::Error> {
        let body = DnsConfigUpdate {
            upstream_dns: upstreams,
        };

        self.client
            .post(format!("{}/control/dns_config", self.base_url))
            .timeout(self.api_timeout)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    pub async fn get_upstreams(&self) -> Result<Vec<String>, reqwest::Error> {
        let response = self
            .client
            .get(format!("{}/control/dns_info", self.base_url))
            .timeout(self.api_timeout)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?
            .error_for_status()?
            .json::<DnsInfo>()
            .await?;
        Ok(response.upstream_dns)
    }

    pub async fn failover(&mut self) {
        match self.set_upstreams(&self.standby_upstreams).await {
            Ok(_) => {
                // キャッシュ削除の成否にかかわらず、上流設定の変更自体は反映済み。
                let _ = self.cache_clear().await;
                self.active_dns = ActiveDns::Fallback;
            }
            // 失敗時は内部状態を維持し、次回の監視ループで再試行できるようにする。
            Err(e) => eprintln!("Failover error: {e}"),
        }
    }

    pub async fn failback(&mut self) {
        match self.set_upstreams(&self.active_upstreams).await {
            Ok(_) => {
                let _ = self.cache_clear().await;
                self.active_dns = ActiveDns::Primary;
            }
            // 復帰に失敗した場合も、次回の再試行のため内部状態を維持する。
            Err(e) => eprintln!("Failback error: {e}"),
        }
    }

    pub async fn cache_clear(&self) -> Result<(), reqwest::Error> {
        self.client
            .post(format!("{}/control/cache_clear", self.base_url))
            .timeout(self.api_timeout)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

#[derive(Serialize)]
pub struct DnsConfigUpdate<'a> {
    upstream_dns: &'a [String],
}

#[derive(Deserialize)]
struct ServerStatus {
    running: bool,
}

#[derive(Debug, Deserialize)]
pub struct DnsInfo {
    upstream_dns: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthCheckState;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn classifies_upstreams_without_relying_on_order() {
        let client = AdGuardClient::new(
            "test".into(),
            "http://localhost".into(),
            vec!["10.0.0.1".into(), "10.0.0.2".into()],
            vec!["1.1.1.1".into(), "8.8.8.8".into()],
            String::new(),
            String::new(),
        );
        assert_eq!(
            client.classify_upstreams(&["10.0.0.2".into(), "10.0.0.1".into()]),
            ActiveDns::Primary
        );
        assert_eq!(
            client.classify_upstreams(&["8.8.8.8".into(), "1.1.1.1".into()]),
            ActiveDns::Fallback
        );
        for upstreams in [
            vec![],
            vec!["9.9.9.9".into()],
            vec!["10.0.0.1".into()],
            vec!["10.0.0.1".into(), "1.1.1.1".into()],
        ] {
            assert_eq!(client.classify_upstreams(&upstreams), ActiveDns::Unknown);
        }
    }

    async fn check_response(
        status: &str,
        body: &str,
        delay: Duration,
    ) -> (AdGuardClient, Result<(), HealthCheckError>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /control/status HTTP/1.1"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: basic ")
            );
            thread::sleep(delay);
            let _ = socket.write_all(response.as_bytes());
        });
        let mut client = AdGuardClient::new(
            "test".into(),
            format!("http://{address}"),
            vec![],
            vec![],
            "admin".into(),
            "password".into(),
        );
        // ローカルテストは環境の HTTP プロキシを使わない。
        client.api_timeout = Duration::from_millis(100);
        client.client = Client::builder().no_proxy().build().unwrap();
        let result = client
            .check_health(
                crate::config::AdGuardHealthCheckMode::Control,
                "google.com",
                Duration::from_millis(100),
                1,
            )
            .await;
        handle.join().unwrap();
        (client, result)
    }

    #[tokio::test]
    async fn checks_running_status_http_errors_and_invalid_json() {
        let (client, result) =
            check_response("200 OK", r#"{"running":true}"#, Duration::ZERO).await;
        assert!(result.is_ok());
        assert_eq!(client.monitor.state, HealthCheckState::Up);
        for (status, body) in [
            ("200 OK", r#"{"running":false}"#),
            ("200 OK", "{}"),
            ("200 OK", "invalid-json"),
            ("401 Unauthorized", "{}"),
            ("500 Internal Server Error", "{}"),
        ] {
            let (client, result) = check_response(status, body, Duration::ZERO).await;
            assert!(matches!(result, Err(HealthCheckError::Api(_))));
            assert_eq!(client.monitor.state, HealthCheckState::Down);
        }
    }

    #[tokio::test]
    async fn dns_mode_records_failures_and_honors_retry() {
        let mut client = AdGuardClient::new(
            "test".into(),
            "invalid-url".into(),
            vec![],
            vec![],
            String::new(),
            String::new(),
        );
        for attempt in 1..=2 {
            let result = client
                .check_health(
                    crate::config::AdGuardHealthCheckMode::Dns,
                    "example.com",
                    Duration::from_secs(1),
                    2,
                )
                .await;
            assert!(matches!(result, Err(HealthCheckError::Dns(_))));
            assert_eq!(client.monitor.consecutive_failed, attempt);
            assert_eq!(
                client.monitor.state,
                if attempt == 2 {
                    HealthCheckState::Down
                } else {
                    HealthCheckState::Unknown
                }
            );
        }
    }

    #[tokio::test]
    async fn normal_api_requests_have_a_timeout() {
        for endpoint in ["dns_info", "dns_config", "cache_clear"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buffer = [0; 4096];
                let count = socket.read(&mut buffer).unwrap();
                assert!(
                    String::from_utf8_lossy(&buffer[..count])
                        .contains(&format!("/control/{endpoint}"))
                );
                // dns_info はヘッダー受信後の本文待ちにも制限が適用されることを確認。
                if endpoint == "dns_info" {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 19\r\n\r\n").unwrap();
                }
                thread::sleep(Duration::from_millis(250));
            });
            let mut client = AdGuardClient::new(
                "test".into(),
                format!("http://{address}"),
                vec![],
                vec![],
                String::new(),
                String::new(),
            )
            .with_api_timeout(Duration::from_millis(100));
            client.client = Client::builder().no_proxy().build().unwrap();
            let error = match endpoint {
                "dns_info" => client.get_upstreams().await.unwrap_err(),
                "dns_config" => client.set_upstreams(&[]).await.unwrap_err(),
                _ => client.cache_clear().await.unwrap_err(),
            };
            assert!(error.is_timeout(), "{endpoint}: {error}");
            handle.join().unwrap();
        }
    }

    #[tokio::test]
    async fn times_out() {
        let (client, result) =
            check_response("200 OK", r#"{"running":true}"#, Duration::from_millis(250)).await;
        assert!(matches!(result, Err(HealthCheckError::Timeout)));
        assert_eq!(client.monitor.state, HealthCheckState::Down);
    }
}
