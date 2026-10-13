# Hypershield Failure Test Monitor

Smart Switch配下のWindows VMから、複数宛先の通信状態を並列監視する試験用ツールです。

- ICMP: Windows標準の`ping.exe`
- TCP: `iperf3`クライアント
- UDP: `iperf3`クライアント

通信できれば緑、通信できなければ赤、未判定は灰色で表示します。Allow／Denyなどの期待値判定は行いません。Smart Switchの障害注入と復旧操作は人が行い、このツールは通信状態、測定値、時刻、不通時間を記録します。

## 必要環境

- Windows 10／11またはWindows Server
- Python 3.9以降
- Windows VM上の`iperf3.exe`
- TCP／UDP試験の各宛先で稼働する`iperf3`サーバー
- Smart Switch操作用の独立した管理端末またはOOB経路

Pythonの外部パッケージは不要です。

> `iperf3`はESnetの公式見解ではWindowsを正式サポートしていません。利用するWindowsビルドのバージョンとSHA256を固定し、試験前に同じバイナリで疎通とJSON出力を確認してください。詳細は[iperf3 FAQ](https://software.es.net/iperf/faq.html)を参照してください。

## 対向ホストの準備

同じ対向ホストへTCPとUDPを並列実行する場合は、別々のポートで`iperf3`サーバーを2プロセス起動します。

```bat
C:\Tools\iperf3\iperf3.exe -s -p 5201
C:\Tools\iperf3\iperf3.exe -s -p 5202
```

- 5201: TCP試験用。Windows FirewallでTCP/5201を許可します。
- 5202: UDP試験用。Windows FirewallでTCP/5202とUDP/5202の両方を許可します。
- UDP試験でも、iperf3は最初にTCP制御接続を使用します。UDPだけを許可してTCP/5202を遮断すると、UDPデータの試験を開始できません。
- 1つのiperf3サーバープロセスは同時に1テストだけ処理します。このため、本ツールは同じ宛先IP・同じポートの重複設定をエラーにします。

オプションの詳細は[iperf3公式ドキュメント](https://software.es.net/iperf/invoking.html)を参照してください。

## Windows VMへの導入

1. このフォルダーをWindows VMへコピーします。
2. `config.example.json`を`config.json`へコピーします。
3. `config.json`の宛先IP、ポート、`iperf3.exe`のパスを変更します。
4. 対向ホストのiperf3サーバーを起動します。
5. `run_monitor.bat`を実行します。
6. ブラウザで`http://localhost:8765`を開きます。

コマンドプロンプトから実行する場合:

```bat
py -3 monitor.py --config config.json
```

停止はコマンドプロンプトで`Ctrl+C`を押します。画面の「試験終了を記録」は時刻を記録するだけで、プロセスは停止しません。

## 設定

共通のiperf3設定:

```json
"iperf3": {
  "executable": "C:\\Tools\\iperf3\\iperf3.exe",
  "duration_seconds": 2,
  "connect_timeout_ms": 800,
  "tcp_bitrate": "1M",
  "udp_bitrate": "1M",
  "reverse": false
}
```

試験対象の例:

```json
"probes": [
  {
    "id": "gateway_ping",
    "name": "Gateway ICMP",
    "type": "ping",
    "host": "10.10.10.1"
  },
  {
    "id": "server_a_tcp",
    "name": "Server A TCP",
    "type": "tcp",
    "host": "10.10.20.20",
    "port": 5201,
    "bitrate": "1M"
  },
  {
    "id": "server_a_udp",
    "name": "Server A UDP",
    "type": "udp",
    "host": "10.10.20.20",
    "port": 5202,
    "bitrate": "1M"
  }
]
```

| 設定 | 意味 |
|---|---|
| `type` | `ping`、`tcp`、`udp`。`icmp`も`ping`として扱います |
| `interval_seconds` | 各試験の開始間隔。既定値3秒 |
| `timeout_seconds` | Pingの応答待ち時間。既定値0.8秒 |
| `duration_seconds` | iperf3の1回の測定時間。既定値2秒 |
| `connect_timeout_ms` | iperf3のTCP制御接続タイムアウト |
| `bitrate` | 対象別の送信レート。未指定時は共通設定を使用 |
| `reverse` | `true`なら対向からWindows VMへ送信 |
| `enabled` | `false`なら対象外 |

到達性確認が目的のため、初期値は`-P 1`、1 Mbps、2秒の低負荷です。TCP／UDP試験はiperf3処理時間を含むため、Pingほど短い間隔では判定されません。

## 判定

- Ping: `ping.exe`がICMP Echo Replyを受信すると「通信成立」
- TCP: iperf3の受信側集計で受信バイトが1以上なら「通信成立」
- UDP: iperf3の受信側集計で受信パケットが1以上なら「通信成立」
- 実行ファイル不在、タイムアウト、制御接続失敗、JSON異常、受信データ0は「通信不成立」

UDPロス率とTCP／UDPスループットは画面・CSVへ記録しますが、しきい値による品質判定は行いません。そのため、高ロスでも1パケット以上届けば緑です。通信品質を合否に含める場合は、試験項目側で別途しきい値を定義してください。

## 障害試験の流れ

1. 監視を開始し、60～120秒、全対象が緑で安定することを確認します。
2. 「障害開始を記録」を押します。
3. 別の管理端末からSmart Switchを手動操作します。
4. 対象通信が赤になる時刻と不通時間を確認します。
5. Smart Switchを手動で復旧します。
6. 「復旧操作を記録」を押します。
7. 対象通信が緑へ戻り、安定することを確認します。
8. 「試験終了を記録」を押し、`Ctrl+C`で停止します。

## 証跡

実行ごとに次のファイルを作成します。

```text
logs/YYYYMMDD_HHMMSS_<run-id>/
  run.json
  probe_results.csv
  events.jsonl
```

- `probe_results.csv`: 全通信試行、スループット、ロス率、連続不通回数、不通時間
- `events.jsonl`: 状態変化と手動操作マーカー
- `run.json`: 開始時刻、実行環境、使用した設定

CSVはExcelで開けるUTF-8 BOM付きです。各試行後に保存するため、RDPが切断してもそれまでの記録は残ります。

## 注意事項

- 色は実際の疎通結果だけを示します。PolicyのAllow／Denyと照合した最終合否は、試験表側で判断してください。
- 不通だけでは「Hypershield Policy遮断」「経路断」「対向iperf3停止」を区別できません。Timescape／Nexus Dashboardのログや対向ホストの状態と突合してください。
- ICMPをPolicyの代表判定に使わず、TCP／UDPも確認してください。
- 宛先にはIPアドレスを推奨します。ホスト名ではDNS障害も結果に含まれます。
- Windows VMからSmart Switchを操作しないでください。復旧操作は独立した管理経路から行います。
- `dashboard.listen`は初期値`127.0.0.1`です。必要性を確認せず`0.0.0.0`へ変更しないでください。
- Windowsの時刻同期、スリープ無効化、Windows Firewall、ウイルス対策製品の影響を事前に確認してください。
