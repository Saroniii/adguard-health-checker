# adguard-health-checker

## 設定と起動

`config.example.toml` を `config.toml` にコピーし、AdGuard Home の URL、認証情報、切り替え先 DNS を設定します。

```powershell
Copy-Item config.example.toml config.toml
cargo run
```

既定ではカレントディレクトリの `config.toml` を読み込みます。コンフィグを指定する場合は引数で指定できます。

```powershell
cargo run -- path/to/config.toml
```

`[[adguard_servers]]` を追加すると複数台を設定できます。各項目は必須です。

- `name`: サーバー名
- `base_url`: AdGuard Home の管理画面の URL（`/control` は含めない）
- `api_timeout_sec`: AdGuard API の各リクエストのタイムアウト秒数。1以上、省略時5秒。初回取得・設定変更・キャッシュ削除・Control 方式のヘルスチェックに適用（本文受信を含む）
- `username` / `password`: API 認証情報
- `active_upstreams`: Primary 使用時の上流 DNS 一覧
- `standby_upstreams`: Fallback 使用時の上流 DNS 一覧

設定の読み込みや検証に失敗した場合は、監視を開始せず終了します。
認証情報を含む `config.toml` は Git の追跡対象から除外しています。

## 監視設定

`[monitor]` で監視条件を指定します。すべて必須です。

```toml
[monitor]
retry = 3
timeout_sec = 5
interval_sec = 5
query_fqdn = "google.com"
```

- `retry`: 連続失敗回数の上限（旧 `max_try`）。1以上
- `timeout_sec`: DNS ヘルスチェックのタイムアウト秒数。1以上
- `interval_sec`: 監視間隔の秒数。`timeout_sec` 以上
- `query_fqdn`: ヘルスチェックで A レコードを問い合わせるドメイン

## 監視対象 DNS

`[[dns_servers]]` ごとに監視対象を追加します。すべて必須です。

```toml
[[dns_servers]]
name = "primary-dns"
state_group = "primary"
ip = "192.0.2.10"
protocol = "udp"
```

`state_group` は `primary` / `fallback`、`protocol` は `udp` / `tcp` / `doh` を指定します。
`ip` は IPv4 / IPv6 アドレスです。UDP/TCP の通信ポートは53です。
Primary を1台以上設定してください。切り替え・復帰の判定は既存どおり Primary の状態を基準にします。

Primary が全台 Down の場合、Fallback に1台以上 Up が確認できたときだけ切り替えます。
Fallback が未設定、全台 Down、または Up が未確認の場合は切り替えを見送り、ログに記録します。
切り替え先の `standby_upstreams` に対応する監視対象を `state_group = "fallback"` で登録してください。
Primary 全台 Up で復帰します。すでに切り替え先を使用している AdGuard への再設定は行いません。

起動時の上流 DNS は並び順を無視して Primary / Fallback の設定と比較します。
どちらとも一致しない場合は Unknown としてログに記録します。
Unknown でも監視結果に応じた自動切り替え・復帰の対象となります。

設定変更は再起動後に反映されます。

### DoH

```toml
[[dns_servers]]
name = "cloudflare-doh"
state_group = "fallback"
ip = "1.1.1.1"
protocol = "doh"
server_name = "cloudflare-dns.com"
path = "/dns-query"
port = 443
```

`server_name` は必須で、TLS 証明書の検証と SNI に使用するホスト名を指定します。
URL ではなくホスト名のみ指定してください。接続先は `ip` を使用します。
`path` は省略時 `/dns-query`、`port` は省略時443です。これら3項目は DoH 専用です。
HTTP/2 の DoH を使用し、公開ルート証明書で TLS 証明書を検証します。
AdGuard 本体の `adguard_health_check_mode = "dns"` は引き続き UDP/53 です。

## AdGuard 本体のヘルスチェック

`[monitor]` の `adguard_health_check = true` で有効、`false` で無効にします。
省略時は無効です。全 AdGuard サーバーに共通で適用されます。

`adguard_health_check_mode = "control"`（省略時も control）または `"dns"` で判定方式を選択します。

`control` は監視ループごとに認証付き `GET /control/status` を実行し、
正常な JSON 応答で `running = true` なら Up とします。
HTTP エラー、JSON 不正、`running = false`、通信失敗、タイムアウトを失敗として記録し、
`retry` 回連続失敗すると Down、成功すると Up に復帰します。結果と状態はログに表示します。
`interval_sec`、`retry` は DNS 監視と共通です。
Control 方式のタイムアウトは各 `[[adguard_servers]]` の `api_timeout_sec`、DNS 方式は `[monitor]` の `timeout_sec` を使います。

`dns` は各 AdGuard の `base_url` のホストへ UDP/53 で `query_fqdn` の A レコードを問い合わせます。
管理画面のポートは使用しません。ホスト名の場合はシステムの名前解決で最初に得られた IP を使用します。
DNS 応答の成功・失敗を判定し、Control API の状態はチェックしません。

この監視は状態の記録・ログ表示を行います。DNS の切り替え条件は変更しません。
無効時も、起動時の上流 DNS 設定取得と必要な切り替え API は実行します。
