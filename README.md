# adguard-health-checker

AdGuard Home の上流 DNS を監視し、障害時に予備の DNS へ自動で切り替える Rust 製ツールです。Linux での利用を想定しています。

- **Primary**：通常使う上流 DNS
- **Fallback**：障害時に使う予備の上流 DNS

## はじめに

Rust の stable ツールチェーン（`rustc` / `cargo`）を事前にインストールしてください。実行するホストから、監視先 DNS と AdGuard Home の管理 API に接続できる必要があります。

### 1. ビルドする

Ubuntu / Debian の例です。

```bash
sudo apt-get update
sudo apt-get install -y git build-essential cmake pkg-config ca-certificates

git clone https://github.com/Saroniii/adguard-health-checker.git
cd adguard-health-checker
cargo build --release --locked
```

### 2. 設定する

```bash
cp config.example.toml config.toml
chmod 600 config.toml
vi config.toml
```

[設定例](config.example.toml)の値を、実環境に合わせて変更します。特に次の3点を確認してください。

| 設定箇所 | 設定する内容 |
| --- | --- |
| `[monitor]` | 監視間隔・失敗回数・問い合わせるドメイン |
| `[[dns_servers]]` | Primary と Fallback の監視先 IP・通信方式 |
| `[[adguard_servers]]` | AdGuard Home の URL・認証情報・切り替え先 DNS |

`active_upstreams` に通常の DNS、`standby_upstreams` に予備の DNS を指定します。それぞれに対応する監視先を `dns_servers` に登録してください。

設定例の IP・URL・パスワードはダミーです。そのままでは利用できません。

### 3. 起動する

```bash
./target/release/adguard-health-checker ./config.toml
```

監視結果は端末に出力されます。終了は `Ctrl+C` です。

設定ファイルは引数で指定できます。省略すると、カレントディレクトリの `config.toml` を読み込みます。設定を変更したら再起動してください。

## 自動切り替えの条件

| 監視状態 | 動作 |
| --- | --- |
| Primary が全台 Down、Fallback が1台以上 Up | 予備の DNS へ切り替える（Failover） |
| Primary が全台 Up | 通常の DNS へ戻す（Failback） |
| それ以外 | 現在の設定を維持する |

各 DNS は `retry` 回連続で失敗すると Down、1回成功すると Up になります。起動直後の未確認状態は Unknown です。

**Fallback の監視先が未登録、または1台も Up でなければ、自動切り替えは行いません。**

## 設定項目

### 監視条件：`[monitor]`

| 項目 | 内容 |
| --- | --- |
| `retry` | Down と判定する連続失敗回数。1以上 |
| `timeout_sec` | DNS 問い合わせのタイムアウト秒数。1以上 |
| `interval_sec` | 監視間隔の秒数。`timeout_sec` 以上 |
| `query_fqdn` | A レコードを問い合わせるドメイン |
| `adguard_health_check` | AdGuard 本体も監視するか。省略時 `false` |
| `adguard_health_check_mode` | 本体の監視方式。`control`（既定）または `dns` |

`retry` は1回の監視内での再送回数ではなく、監視をまたいだ連続失敗回数です。

### DNS 監視先：`[[dns_servers]]`

監視する DNS ごとに追加します。Primary は1台以上必要です。

| 項目 | 内容 |
| --- | --- |
| `name` | ログに表示する名前 |
| `state_group` | `primary` または `fallback` |
| `ip` | 接続先の IPv4 / IPv6 アドレス |
| `protocol` | `udp` / `tcp` / `doh` |

UDP / TCP はポート53を使用します。DoH の場合は次の項目も指定します。

| DoH 専用項目 | 内容 |
| --- | --- |
| `server_name` | 必須。TLS 証明書の検証に使うホスト名（URL は不可） |
| `path` | 省略時 `/dns-query` |
| `port` | 省略時 `443` |

DoH の記入例は [config.example.toml](config.example.toml) にあります。

### AdGuard Home：`[[adguard_servers]]`

設定を変更する AdGuard Home ごとに追加します。1台以上必要です。

| 項目 | 内容 |
| --- | --- |
| `name` | ログに表示する名前 |
| `base_url` | 管理画面の URL。末尾に `/control` を付けない |
| `username` / `password` | 管理 API の認証情報 |
| `active_upstreams` | Primary 使用時の上流 DNS 一覧 |
| `standby_upstreams` | Fallback 使用時の上流 DNS 一覧 |
| `api_timeout_sec` | 管理 API のタイムアウト秒数。1以上、省略時 `5` |

## AdGuard 本体の監視（任意）

`adguard_health_check = true` で有効になります。結果の記録・表示用で、上流 DNS の切り替え条件には影響しません。

| 方式 | 確認する内容 | タイムアウト |
| --- | --- | --- |
| `control` | 管理 API の `/control/status` が `running = true` を返すか | `api_timeout_sec` |
| `dns` | `base_url` のホストへ UDP/53 で名前解決できるか | `timeout_sec` |

本体の監視を無効にしても、上流 DNS の取得・切り替えには管理 API を使います。

## 運用上の注意

- `config.toml` にはパスワードが含まれます。Git の追跡対象からは除外しています。
- 起動時に AdGuard Home の上流設定を取得します。Primary / Fallback のどちらとも一致しない場合も、自動切り替えの対象になります。
- 稼働中に管理画面などで上流設定を変更しても、内部状態には自動反映されません。変更後は本ツールを再起動してください。
- 設定ファイルの読み込みや検証に失敗した場合は、監視を開始せず終了します。
