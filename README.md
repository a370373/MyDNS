## 🌐 MyDNS Server

«🧠 My DNS. My Resolver.

一個使用 Rust 從零實作的 Self-Hosted Recursive DNS Resolver。

不依賴 ISP DNS，也不需要依賴 Cloudflare、Google 等公共 DNS 服務。
MyDNS 會自行從 DNS Root → TLD → Authoritative DNS 進行遞迴解析，取得目前最新的 DNS 資料。»

---

## ✨ MyDNS 是什麼？

MyDNS 的目標很簡單：

«讓使用者自己擁有一個 DNS Recursive Resolver。»

傳統情況：

你的裝置
   │
   ▼
ISP DNS / 公共 DNS
   │
   ▼
Internet DNS

MyDNS：

你的裝置
   │
   ▼
┌──────────────┐
│    MyDNS     │
│              │
│ Recursive    │
│ Resolver     │
│ Cache        │
└──────┬───────┘
       │
       ▼
 Root DNS
       │
       ▼
 TLD DNS
       │
       ▼
Authoritative DNS

🌱 MyDNS 不保存一份固定的「網站 IP 清單」。

網站今天換 IP、明天換 IP：

example.com
    ↓
Authoritative DNS
    ↓
取得目前最新結果

MyDNS 只負責按照 DNS 協定去取得資料並依 TTL 快取。

因此：

«🌐 網站換 IP，不需要重新更新 MyDNS 程式。»

---

## 🚀 目前已實作功能

🔎 Recursive DNS Resolution

MyDNS 可以自行進行：

Root
 ↓
TLD
 ↓
Authoritative DNS
 ↓
取得最終 DNS Record

不需要把 ISP DNS 當作上游 Recursive DNS。

---

## 🔁 CNAME Recursive Resolution

支援 CNAME 遞迴：

example.com
     │
     ▼
CNAME
     │
     ▼
another.example.net
     │
     ▼
A / AAAA

MyDNS 會繼續解析 CNAME 指向的名稱，直到取得最終結果。

並保留 CNAME 與最終 Record。

---

## 🌐 HTTPS Record

支援：

TYPE 65
HTTPS

可以解析與回傳 HTTPS DNS Record。

---

## 🧩 Generic DNS Record Structure

目前使用統一的：

DnsRecord

表示不同 DNS Record：

A
AAAA
CNAME
HTTPS

每個 Record 都可以取得：

Name
TTL
Record Type

方便後續擴充更多 DNS Record Type。

---

## ⚡ DNS Cache

MyDNS 內建 DNS Cache：

Client
  │
  ▼
MyDNS
  │
  ├── Cache Hit ──→ 直接回覆
  │
  └── Cache Miss
          │
          ▼
     Recursive Resolve

Cache 會依照 DNS Record 的 TTL 過期。

因此：

TTL 到期
   ↓
重新向 DNS Server 查詢
   ↓
取得新的資料
   ↓
重新 Cache

🌱 不需要人工更新網站 IP。

---

## 📦 EDNS

目前支援基本 EDNS：

EDNS
UDP Payload Size

預設使用：

1232 bytes

MyDNS 可以解析 DNS Query 中的 OPT Record，並在 Response 中加入基本 EDNS Response。

---

## 📡 DNS Protocol

MyDNS Server 目前提供：

## 🟢 UDP DNS

127.0.0.1:53

Native 模式。

Termux 模式：

127.0.0.1:15353

---

## 🟢 TCP DNS

與 UDP DNS 使用相同的 Resolver / Cache。

TCP DNS 使用標準 DNS TCP：

┌──────────┐
│ 2 bytes  │
│ length   │
└────┬─────┘
     │
     ▼
 DNS Packet

因此 UDP 與 TCP 不需要各自維護一套 DNS Resolver。

---

## 🔐 DNS over HTTPS

MyDNS 也提供 DoH：

/dns-query

使用 HTTPS 傳輸 DNS Query。

架構：

Application
    │
    ▼
 HTTPS
    │
    ▼
 MyDNS DoH
    │
    ▼
 DnsService
    │
    ▼
Recursive Resolver

目前 DoH 支援：

GET /dns-query
POST /dns-query

---

## 🔒 Local HTTPS Certificate

MyDNS 第一次啟動時會建立本機使用的 TLS 憑證：

certs/
├── mydns-ca.pem
├── mydns-cert.pem
└── mydns-key.pem

⚠️ "certs/" 不會放進 GitHub Repository。

因為這些是本機執行環境產生的憑證。

如果其他裝置要信任 MyDNS 的 HTTPS，需要將：

mydns-ca.pem

加入該裝置的信任憑證。

---

## 📱 Android / Termux

MyDNS 可以直接在 Android 的 Termux 執行。

目前 Termux 測試模式：

DNS
127.0.0.1:15353

DoH
https://127.0.0.1:18443/dns-query

啟動：

cd ~/MyDNS
cargo run -- --mode=termux

或者使用已編譯的程式：

./target/debug/MyDNS --mode=termux

啟動後可以看到：

MyDNS Server
Mode: termux
DNS: 127.0.0.1:15353
DoH: https://127.0.0.1:18443/dns-query
MyDNS UDP listening on 127.0.0.1:15353
MyDNS TCP listening on 127.0.0.1:15353
MyDNS DoH listening on https://127.0.0.1:18443/dns-query

📱 Android 上可以讓本機應用程式或測試環境使用這個 Resolver。

---

## 🐧 Linux

Linux 使用 Native 模式：

DNS
127.0.0.1:53

DoH
https://127.0.0.1:443/dns-query

執行：

cargo run -- --mode=native

或者：

./target/debug/MyDNS --mode=native

⚠️ Port "53" 和 "443" 通常需要適當的權限。

可以使用：

sudo

或使用其他方式讓 MyDNS 取得必要的網路埠權限。

---

## 🪟 Windows

Windows 同樣可以執行 MyDNS。

首先安裝：

- Rust
- Cargo

然後取得專案：

git clone https://github.com/a370373/MyDNS.git
cd MyDNS

編譯：

cargo build --release

執行：

cargo run --release -- --mode=native

或：

target\release\MyDNS.exe --mode=native

Native 模式：

DNS
127.0.0.1:53

DoH
https://127.0.0.1:443/dns-query

Windows 如果需要監聽 "53" / "443"，需要確認系統權限以及是否有其他程式佔用這些 Port。

---

## 💻 PC 使用方式

Linux / Windows / 其他支援 Rust 的環境，都可以將 MyDNS 當成本機 Recursive DNS。

基本架構：

        ┌────────────────────┐
        │      Browser       │
        │     Application    │
        └─────────┬──────────┘
                  │
                  ▼
          ┌───────────────┐
          │    MyDNS      │
          │               │
          │ UDP / TCP     │
          │ DoH           │
          │ Cache         │
          └───────┬───────┘
                  │
                  ▼
             Internet DNS

這樣電腦本身就可以使用自己的 Recursive DNS Resolver。

---

## 🧪 Development / Build

目前 MyDNS 使用：

Rust
Cargo

基本檢查：

cargo check

編譯：

cargo build

Release：

cargo build --release

執行：

cargo run -- --mode=termux

或：

cargo run -- --mode=native

---

## ⚙️ 執行模式

📱 Termux

DNS  : 127.0.0.1:15353
DoH  : 127.0.0.1:18443

適合：

Android
Termux
Development
Testing

---

## 💻 Native

DNS  : 127.0.0.1:53
DoH  : 127.0.0.1:443

適合：

Linux
Windows
PC
Server

---

## 🧠 Architecture

目前大致架構：

MyDNS
│
├── dns/
│   ├── packet.rs
│   ├── query.rs
│   └── record.rs
│
├── resolver/
│   ├── cache.rs
│   ├── recursive.rs
│   ├── root.rs
│   └── service.rs
│
├── server/
│   ├── udp.rs
│   ├── tcp.rs
│   └── doh.rs
│
└── main.rs

核心概念：

             ┌───────────────┐
             │   UDP Server  │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │               │
             │   DnsService  │
             │               │
             │ Cache         │
             │ Resolver      │
             │               │
             └───────┬───────┘
                     │
             ┌───────▼───────┐
             │ Recursive DNS │
             └───────┬───────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
        Root        TLD    Authoritative

UDP、TCP、DoH 都共用同一個：

DnsService

因此不同 DNS 傳輸協定不需要各自實作一套 Resolver。

---

## 🎯 Project Philosophy

MyDNS 並不是要成為另一個：

Cloudflare 1.1.1.1
Google Public DNS

它的目的比較接近：

«🏠 「這是我的 DNS，我自己解析。」»

你不需要把 DNS 查詢交給某一家公共 DNS 服務。

不是：

你 → Cloudflare → Internet

而是：

你 → MyDNS → Root → TLD → Authoritative

這也是 MyDNS 的核心理念：

🔥 My DNS. My Resolver.

---

## 📝 更新策略

MyDNS 不需要因為網站資料改變而更新程式。

例如：

example.com

今天：

1.2.3.4

明天：

5.6.7.8

MyDNS 不需要重新編譯。

因為 MyDNS 取得的是：

DNS Protocol
       ↓
Authoritative DNS
       ↓
目前最新資料

所以：

«🌐 DNS 資料會變，Resolver 程式不需要跟著網站 IP 一起變。»

MyDNS 本身主要在以下情況才需要更新：

- ➕ 新增功能
- 🐛 修正 Bug
- 🔐 修正安全問題
- 📡 支援新的 DNS 標準
- ⚡ 效能改善
- 🧩 支援更多 Record Type

---

## ⚠️ 目前限制

MyDNS 目前仍屬於持續開發中的 Recursive DNS Resolver。

目前尚未以完整功能為目標的部分包括：

- DNSSEC
- 完整 EDNS Option 處理
- 更多 DNS Record Type
- 更完整的 TCP fallback / truncated response handling
- 更完整的 DNS protocol edge-case handling
- Production-grade security hardening

因此目前更適合作為：

🧪 Research
🛠️ Development
🏠 Personal DNS
💻 Self-hosted Resolver

而不是直接宣稱為大型公共 DNS 服務。

---

## 📜 License

目前專案授權方式請以 Repository 中的 License 為準。

---

## 👀 MyDNS

«不要依賴別人的 DNS。

自己跑一個。

🌐 My DNS. My Resolver.»

---

## 📬 聯繫創作者

- Instagram：[a370373/XRH](https://instagram.com/a370373)
- 本人17歲🤔 做的不好請見諒
- 獨立開發 ＆ AI協作
- 緩慢更新 ＆ 除錯
- 純手機Termux 開發👀
- 持續開發中…

---

## 👀作品 & 產品 集

- [MyDNS](https://github.com/a370373/MyDNS/tree/main)
- [Cyber-Fly-Android-Bridge](https://github.com/a370373/Cyber-Fly-Android-Bridge)
- [My-ADB-Shell](https://github.com/a370373/My-ADB-Shell/tree/main)
- [Cyber-Fly](https://github.com/a370373/Cyber-Fly)
- [MyOS](https://github.com/a370373/MyOS)
- [RWM-1:1 Real World Minecraft](https://github.com/a370373/RWM-Real-World-Minecraft)
- [MyAI-Offline Personal AI Agent System](https://github.com/a370373/MyAI-Offline-Personal-AI-Agent-System-/tree/main)
- [WCL - Web Clone Lab](https://github.com/a370373/web-clone-lab/)
- 持續增加中…👀

---

## 🤖 AI 協作

MyDNS 由 a370373/XRH 發起、設計與開發。

開發過程中使用 OpenAI ChatGPT 作為 AI 協作夥伴，協助進行 技術分析、程式碼檢查、除錯 & 文件整理。

產品方向、設計理念 & 最終決策由專案創作者負責。
