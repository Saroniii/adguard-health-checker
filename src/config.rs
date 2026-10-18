use std::{fs, net::IpAddr, path::Path};

use serde::Deserialize;

use crate::{
    api::{ActiveDns, AdGuardClient},
    dns::{DNSServerType, DnsServer},
};

pub struct Config {
    pub monitor: MonitorConfig,
    pub dns_servers: Vec<DnsConfig>,
    pub adguard_servers: Vec<AdGuardClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    #[serde(default)]
    pub adguard_health_check_mode: AdGuardHealthCheckMode,
    #[serde(default)]
    pub adguard_health_check: bool,
    pub retry: u32,
    pub timeout_sec: u64,
    pub interval_sec: u64,
    pub query_fqdn: String,
}

#[derive(Default, Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdGuardHealthCheckMode {
    Dns,
    #[default]
    Control,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    name: String,
    state_group: DnsGroup,
    ip: IpAddr,
    protocol: Protocol,
    server_name: Option<String>,
    path: Option<String>,
    port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DnsGroup {
    Primary,
    Fallback,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Udp,
    Tcp,
    Doh,
}

impl DnsConfig {
    pub fn into_server(self) -> DnsServer {
        DnsServer::new(
            self.name,
            match self.state_group {
                DnsGroup::Primary => ActiveDns::Primary,
                DnsGroup::Fallback => ActiveDns::Fallback,
            },
            self.ip,
            match self.protocol {
                Protocol::Udp => DNSServerType::Udp,
                Protocol::Tcp => DNSServerType::Tcp,
                Protocol::Doh => DNSServerType::DoH {
                    server_name: self.server_name.unwrap_or_default(),
                    path: self.path.unwrap_or_else(|| "/dns-query".into()),
                    port: self.port.unwrap_or(443),
                },
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    monitor: MonitorConfig,
    dns_servers: Vec<DnsConfig>,
    adguard_servers: Vec<AdGuardConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdGuardConfig {
    #[serde(default = "default_api_timeout_sec")]
    api_timeout_sec: u64,
    name: String,
    base_url: String,
    active_upstreams: Vec<String>,
    standby_upstreams: Vec<String>,
    username: String,
    password: String,
}

fn default_api_timeout_sec() -> u64 {
    5
}

pub fn load(path: impl AsRef<Path>) -> Result<Config, String> {
    let contents =
        fs::read_to_string(path).map_err(|error| format!("読み込みに失敗しました: {error}"))?;
    parse(&contents)
}

fn parse(contents: &str) -> Result<Config, String> {
    // TOML のエラー全文には認証情報を含む入力行が表示されるため出力しない。
    let config: FileConfig = toml::from_str(contents).map_err(|error: toml::de::Error| {
        let line = error.span().map(|span| {
            contents[..span.start]
                .bytes()
                .filter(|&byte| byte == b'\n')
                .count()
                + 1
        });
        match line {
            Some(line) => format!("TOML の構文または設定項目が不正です（{line}行目）"),
            None => "TOML の構文または設定項目が不正です".to_owned(),
        }
    })?;

    if config.monitor.retry == 0
        || config.monitor.timeout_sec == 0
        || config.monitor.interval_sec == 0
    {
        return Err("retry、timeout_sec、interval_sec は1以上を指定してください".into());
    }
    if config.monitor.timeout_sec > config.monitor.interval_sec {
        return Err("timeout_sec は interval_sec 以下に設定してください".into());
    }
    if hickory_resolver::proto::rr::Name::from_ascii(&config.monitor.query_fqdn).is_err()
        || config.monitor.query_fqdn.trim().is_empty()
    {
        return Err("query_fqdn が不正です".into());
    }
    if !config
        .dns_servers
        .iter()
        .any(|server| matches!(server.state_group, DnsGroup::Primary))
    {
        return Err("dns_servers に primary を1件以上指定してください".into());
    }
    if config
        .dns_servers
        .iter()
        .any(|server| server.name.trim().is_empty())
    {
        return Err("dns_servers の name が空です".into());
    }
    if config.adguard_servers.is_empty() {
        return Err("adguard_servers を1件以上指定してください".into());
    }

    for (index, server) in config.dns_servers.iter().enumerate() {
        let invalid = |field| format!("dns_servers の{}件目: {field} が不正です", index + 1);
        if matches!(server.protocol, Protocol::Doh) {
            let name = server
                .server_name
                .as_deref()
                .ok_or_else(|| invalid("server_name"))?;
            if name.is_empty()
                || name.trim() != name
                || name.contains(['/', ':', '@', '?', '#'])
                || hickory_resolver::proto::rr::Name::from_ascii(name).is_err()
            {
                return Err(invalid("server_name"));
            }
            let path = server.path.as_deref().unwrap_or("/dns-query");
            if !path.starts_with('/')
                || path.starts_with("//")
                || path.contains('#')
                || path
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            {
                return Err(invalid("path"));
            }
            if server.port == Some(0) {
                return Err(invalid("port"));
            }
        } else if server.server_name.is_some() || server.path.is_some() || server.port.is_some() {
            return Err(invalid("server_name/path/port は doh 専用です"));
        }
    }

    let adguard_servers = config
        .adguard_servers
        .into_iter()
        .enumerate()
        .map(|(index, server)| {
            let invalid =
                |field| format!("adguard_servers の{}件目: {field} が不正です", index + 1);
            if server.name.trim().is_empty() {
                return Err(invalid("name"));
            }
            if server.api_timeout_sec == 0 {
                return Err(invalid("api_timeout_sec は1以上を指定してください"));
            }
            let url = reqwest::Url::parse(&server.base_url).map_err(|_| invalid("base_url"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(invalid("base_url"));
            }
            for (field, upstreams) in [
                ("active_upstreams", &server.active_upstreams),
                ("standby_upstreams", &server.standby_upstreams),
            ] {
                if upstreams.is_empty() || upstreams.iter().any(|value| value.trim().is_empty()) {
                    return Err(invalid(field));
                }
            }
            Ok(AdGuardClient::new(
                server.name,
                server.base_url.trim_end_matches('/').to_owned(),
                server.active_upstreams,
                server.standby_upstreams,
                server.username,
                server.password,
            )
            .with_api_timeout(std::time::Duration::from_secs(server.api_timeout_sec)))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Config {
        monitor: config.monitor,
        dns_servers: config.dns_servers,
        adguard_servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../config.example.toml");

    #[test]
    fn loads_multiple_servers_and_initializes_clients() {
        let (_, server) = EXAMPLE.split_once("\n[[adguard_servers]]").unwrap();
        let contents = format!("{EXAMPLE}\n[[adguard_servers]]{server}");
        let config = parse(&contents).unwrap();
        assert_eq!(config.monitor.retry, 3);
        assert_eq!(config.monitor.query_fqdn, "example.com");
        assert_eq!(config.dns_servers.len(), 4);
        let clients = config.adguard_servers;
        assert_eq!(clients.len(), 2);
        assert_eq!(clients[0].name, "adguard-example");
        assert_eq!(clients[0].base_url, "http://192.0.2.20:3000");
        assert_eq!(clients[0].active_upstreams, ["192.0.2.10", "192.0.2.11"]);
        assert_eq!(clients[0].standby_upstreams, ["198.51.100.10", "198.51.100.11"]);
        assert_eq!(clients[0].username, "admin");
        assert_eq!(clients[0].password, "change-me");
        assert_eq!(clients[0].active_dns, crate::api::ActiveDns::Unknown);
    }

    #[test]
    fn validates_api_timeout() {
        assert!(parse(&EXAMPLE.replace("api_timeout_sec = 5", "api_timeout_sec = 0")).is_err());
        assert!(parse(&EXAMPLE.replace("api_timeout_sec = 5", "api_timeout_sec = -1")).is_err());
        assert!(parse(&EXAMPLE.replace("api_timeout_sec = 5", "api_timeout_sec = 10")).is_ok());
        assert!(parse(&EXAMPLE.replace("api_timeout_sec = 5", "")).is_ok());
    }

    #[test]
    fn rejects_empty_missing_and_invalid_settings() {
        assert!(parse("adguard_servers = []").is_err());
        assert!(parse("").is_err());
        assert!(parse(&EXAMPLE.replace("password =", "unknown =")).is_err());
        assert!(parse(&EXAMPLE.replace("http://192.0.2.20:3000", "invalid")).is_err());
        assert!(parse(&EXAMPLE.replace("[\"198.51.100.10\", \"198.51.100.11\"]", "[]")).is_err());
    }

    #[test]
    fn parse_errors_do_not_expose_passwords() {
        let error = parse(&EXAMPLE.replace("\"change-me\"", "\"secret-password\" invalid"))
            .err()
            .unwrap();
        assert!(!error.contains("secret-password"));
    }

    #[test]
    fn validates_monitor_and_dns_settings() {
        for (from, to) in [
            ("retry = 3", "retry = 0"),
            ("timeout_sec = 5", "timeout_sec = 6"),
            ("interval_sec = 5", "interval_sec = 0"),
            ("example.com", ""),
            ("192.0.2.10", "invalid-ip"),
            ("protocol = \"udp\"", "protocol = \"doh\""),
            ("state_group = \"primary\"", "state_group = \"fallback\""),
        ] {
            assert!(parse(&EXAMPLE.replace(from, to)).is_err(), "{from}");
        }
        let config = parse(&EXAMPLE.replace("protocol = \"udp\"", "protocol = \"tcp\"")).unwrap();
        assert!(matches!(config.dns_servers[0].protocol, Protocol::Tcp));
    }

    #[test]
    fn validates_doh_settings() {
        let doh = EXAMPLE.replace(
            "protocol = \"udp\"",
            "protocol = \"doh\"\nserver_name = \"dns.example.com\"",
        );
        let config = parse(&doh).unwrap();
        assert!(matches!(config.dns_servers[0].protocol, Protocol::Doh));
        for extra in [
            "path = \"/custom-query\"\nport = 8443",
            "path = \"/dns-query\"",
        ] {
            assert!(
                parse(&doh.replace(
                    "server_name = \"dns.example.com\"",
                    &format!("server_name = \"dns.example.com\"\n{extra}")
                ))
                .is_ok()
            );
        }
        for extra in [
            "path = \"invalid\"",
            "path = \"//host/query\"",
            "path = \"/query#fragment\"",
            "port = 0",
        ] {
            assert!(
                parse(&doh.replace(
                    "server_name = \"dns.example.com\"",
                    &format!("server_name = \"dns.example.com\"\n{extra}")
                ))
                .is_err()
            );
        }
        assert!(parse(&doh.replace("dns.example.com", "https://dns.example.com")).is_err());
        assert!(parse(&doh.replace("dns.example.com", "")).is_err());
        assert!(
            parse(&EXAMPLE.replace(
                "protocol = \"udp\"",
                "protocol = \"udp\"\nserver_name = \"dns.example.com\""
            ))
            .is_err()
        );
    }

    #[test]
    fn adguard_health_check_can_be_enabled_disabled_or_omitted() {
        assert_eq!(
            parse(EXAMPLE).unwrap().monitor.adguard_health_check_mode,
            AdGuardHealthCheckMode::Control
        );
        assert_eq!(
            parse(&EXAMPLE.replace(
                "adguard_health_check_mode = \"control\"",
                "adguard_health_check_mode = \"dns\""
            ))
            .unwrap()
            .monitor
            .adguard_health_check_mode,
            AdGuardHealthCheckMode::Dns
        );
        assert!(
            parse(&EXAMPLE.replace(
                "adguard_health_check_mode = \"control\"",
                "adguard_health_check_mode = \"invalid\""
            ))
            .is_err()
        );
        assert!(parse(EXAMPLE).unwrap().monitor.adguard_health_check);
        assert!(
            !parse(&EXAMPLE.replace(
                "adguard_health_check = true",
                "adguard_health_check = false"
            ))
            .unwrap()
            .monitor
            .adguard_health_check
        );
        assert!(
            !parse(&EXAMPLE.replace("adguard_health_check = true", ""))
                .unwrap()
                .monitor
                .adguard_health_check
        );
    }
}
