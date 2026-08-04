<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=200&section=header&text=FastNodes&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=The%20World%27s%20Smartest%20Free%20V2Ray%20Collector&descAlignY=58&descSize=18" width="100%"/>

<br/>

[![Update Status](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
![Protocol](https://img.shields.io/badge/Protocols-VLESS%20%7C%20VMess%20%7C%20Trojan%20%7C%20SS%20%7C%20Hysteria2-blueviolet?style=flat-square)
![Update](https://img.shields.io/badge/Auto%20Update-Every%206h-brightgreen?style=flat-square)
![Sources](https://img.shields.io/badge/Sources-150%2B%20repositories-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![Built With](https://img.shields.io/badge/Built%20with-C%23%20.NET%209-purple?style=flat-square)

<br/>

**Collects · Filters · Scores · Categorizes · Publishes**  
*Fully automated. No ads. No login. No BS.*

<br/>

[🚀 Quick Start](#-quick-start) · [📁 All Subscriptions](#-subscription-links) · [⚙️ How It Works](#️-how-it-works) · [📱 Clients](#-compatible-clients) · [🌍 Countries](#️-by-country)

</div>

---

## ✨ What Is FastNodes?

FastNodes is a fully automated V2Ray/Xray proxy aggregator. Every 6 hours it wakes up, fetches configs from **150+ public GitHub repositories**, tears through them with parallel processing, filters out every dead or fake server, scores the survivors by config quality, and publishes clean organized subscriptions — split by protocol, country, and continent.

You get fresh, working proxies in your client without hunting through Telegram channels or sketchy websites. Just copy a link and paste it.

---

## 🚀 Quick Start

The fastest way to get going:

| What | Link |
|------|------|
| **Everything (raw URI list)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt` |
| **Europe (Clash YAML)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Europe.yaml` |
| **Iran nodes** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.txt` |

> **Iran users:** Start with `sub/countries/IR.txt` for domestic servers, then try `sub/continents/Europe.yaml` or `sub/continents/Asia.yaml` for exit nodes. Use a client with built-in latency testing (Hiddify, v2rayNG) to find what works from your ISP.

---

## 📁 Subscription Links

### 🌐 Everything

The full collection — all alive proxies, sorted best-first by quality score.

| Format | URL |
|--------|-----|
| Raw URI (`.txt`) — works in all clients | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt` |

---

### 🔧 By Protocol

Each protocol has both a plain `.txt` (raw URIs, works everywhere) and a `.yaml` (Clash/Mihomo/FLClash, top 1000 quality-sorted nodes).

Base path: `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/`

| Protocol | `.txt` | `.yaml` |
|----------|--------|---------|
| 🔵 VLESS | [vless.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt) | [vless.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.yaml) |
| 🟣 Trojan | [trojan.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt) | [trojan.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.yaml) |
| 🟠 VMess | [vmess.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt) | [vmess.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.yaml) |
| ⚫ Shadowsocks | [ss.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt) | [ss.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.yaml) |
| ⚡ Hysteria2 | [hysteria2.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt) | [hysteria2.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.yaml) |

---

### 🌍 By Continent

Base path: `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/`

| Continent | `.txt` | `.yaml` |
|-----------|--------|---------|
| 🌍 Europe | [Europe.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Europe.txt) | [Europe.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Europe.yaml) |
| 🌏 Asia | [Asia.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Asia.txt) | [Asia.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Asia.yaml) |
| 🌎 North America | [NorthAmerica.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/NorthAmerica.txt) | [NorthAmerica.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/NorthAmerica.yaml) |
| 🌎 South America | [SouthAmerica.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/SouthAmerica.txt) | [SouthAmerica.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/SouthAmerica.yaml) |
| 🌍 Africa | [Africa.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Africa.txt) | [Africa.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Africa.yaml) |
| 🌏 Oceania | [Oceania.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Oceania.txt) | [Oceania.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/Oceania.yaml) |

---

### 🏳️ By Country

Base path: `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/`  
Pattern: `sub/countries/XX.txt` and `sub/countries/XX.yaml` where `XX` is the ISO 3166-1 alpha-2 code.

**Popular countries:**

| | Country | `.txt` | `.yaml` |
|-|---------|--------|---------|
| 🇮🇷 | Iran | [IR.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.txt) | [IR.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.yaml) |
| 🇩🇪 | Germany | [DE.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt) | [DE.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.yaml) |
| 🇺🇸 | United States | [US.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.txt) | [US.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.yaml) |
| 🇳🇱 | Netherlands | [NL.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/NL.txt) | [NL.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/NL.yaml) |
| 🇷🇺 | Russia | [RU.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt) | [RU.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.yaml) |
| 🇫🇷 | France | [FR.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/FR.txt) | [FR.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/FR.yaml) |
| 🇬🇧 | United Kingdom | [GB.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/GB.txt) | [GB.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/GB.yaml) |
| 🇸🇬 | Singapore | [SG.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/SG.txt) | [SG.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/SG.yaml) |
| 🇯🇵 | Japan | [JP.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/JP.txt) | [JP.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/JP.yaml) |
| 🇭🇰 | Hong Kong | [HK.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/HK.txt) | [HK.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/HK.yaml) |
| 🇰🇷 | South Korea | [KR.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/KR.txt) | [KR.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/KR.yaml) |
| 🇫🇮 | Finland | [FI.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/FI.txt) | [FI.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/FI.yaml) |
| 🇨🇭 | Switzerland | [CH.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/CH.txt) | [CH.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/CH.yaml) |
| 🇦🇹 | Austria | [AT.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/AT.txt) | [AT.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/AT.yaml) |
| 🇨🇦 | Canada | [CA.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/CA.txt) | [CA.yaml](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/CA.yaml) |

> About 80 countries are available. Just swap the country code in the URL pattern.

---

## 📱 Compatible Clients

### `.txt` files (raw URI list)

Works in virtually every V2Ray/Xray client:

| Client | Platform | How to import |
|--------|----------|---------------|
| **Hiddify** | Android / iOS / Desktop / Windows | Add Profile → URL → paste `.txt` link |
| **v2rayNG** | Android | Subscription → Add → paste `.txt` link |
| **Exclave** | Android | Add Subscription → paste link |
| **NekoBox** | Android | Profile → New → paste `.txt` link |
| **Shadowrocket** | iOS | Add → Type: Subscribe → paste link |
| **Streisand** | iOS | Add Config → paste link |
| **v2rayN** | Windows | Subscription Group → Add → paste `.txt` link |
| **Nekoray** | Windows / Linux | Preferences → Subscription → paste link |

### `.yaml` files (Clash/Mihomo format)

Contains top 1000 quality-scored nodes with AUTO url-test and MANUAL select groups pre-built. Ideal for:

| Client | Platform |
|--------|----------|
| **FLClash** | Android / Desktop |
| **FlClashX** | macOS |
| **Mihomo Party** | Windows / macOS / Linux |
| **Clash Verge Rev** | Windows / macOS / Linux |
| **OpenClash** | OpenWrt |

> **YAML cap:** Each `.yaml` file contains at most 1000 nodes — the best 1000 by quality score. This keeps file sizes manageable and avoids crashing mobile clients.

---

## ⚙️ How It Works

```
                    ┌─────────────────────────────────────┐
                    │         150+ GitHub Sources          │
                    │  (fetched in parallel, 30 workers)   │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │     Decode & Extract URI Lines       │
                    │  base64 · YAML · HTML · plain text   │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │         Smart Deduplication          │
                    │  key = proto+host+port+uuid+         │
                    │        transport+security            │
                    │  (keeps different UUIDs on same IP)  │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │        CDN & Blacklist Filter        │
                    │  • All 14 Cloudflare CIDR ranges     │
                    │  • FireHOL Level 1 blacklist         │
                    │  • ngrok / workers.dev / etc.        │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │         Quality Scoring              │
                    │  location-agnostic ranking by        │
                    │  protocol · security · transport     │
                    │  · UUID validity · port preference   │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │       TCP Alive Check                │
                    │  200 parallel workers · 3.5s timeout │
                    │  filters truly dead servers          │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                    ┌─────────────────────────────────────┐
                    │  GeoIP Lookup · City / Country DB    │
                    │  parallel cache warm → frozen labels │
                    └──────────────────┬──────────────────┘
                                       │
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                     protocols/   countries/   continents/
                    vless, ss...  IR, DE, US   Europe, Asia
                         +            +            +
                     .txt + .yaml  .txt + .yaml  .txt + .yaml
```

---

## 🏆 Quality Scoring

Proxies are ranked by a **location-agnostic quality score** before sorting. This means the best-configured nodes are always at the top of every file regardless of which GitHub data center runs the check.

| Signal | Score |
|--------|------:|
| Hysteria2 protocol | +100 |
| TUIC protocol | +90 |
| VLESS protocol | +80 |
| Trojan protocol | +70 |
| VMess protocol | +50 |
| Shadowsocks protocol | +40 |
| REALITY security | +30 |
| TLS security | +20 |
| No security | −10 |
| TLS/REALITY on port 80 | −20 |
| xHTTP transport | +12 |
| HTTPUpgrade transport | +10 |
| gRPC transport | +10 |
| WebSocket / H2 transport | +8 |
| SNI configured | +10 |
| Valid UUID format | +15 |
| TLS port (443, 8443, 2053…) | +15 |
| Common HTTP port (80, 8080…) | +8 |

**Result:** VLESS + REALITY + gRPC configs always appear first. Plain VMess with no TLS appears near the bottom.

---

## 🛡️ What Gets Filtered

Every proxy passes through multiple filter stages before making it into any output file:

**CDN / Fake endpoints:**
- All 14 published Cloudflare IPv4 CIDR ranges (ASN 13335) — `104.16.0.0/13`, `172.64.0.0/13`, `162.158.0.0/15`, and 11 more
- Cloudflare WARP ranges
- Known DNS resolvers (`1.1.1.1`, `8.8.8.8`, etc.) which always accept TCP but are not proxies
- Tunneling services: `workers.dev`, `pages.dev`, `trycloudflare.com`, `ngrok.io`, `serveo.net`, etc.

**Malicious IPs:**
- FireHOL Level 1 blacklist — refreshed every run from `iplists.firehol.org`

**Bogus addresses:**
- `0.0.0.0`, `127.0.0.1`, `localhost`

**Protocol validation:**
- VMess base64 must be valid JSON with a resolvable `add` field
- All other protocols must parse as valid URIs with real hostnames/IPs
- Port must be 1–65535

**TCP liveness:**
- Port must accept a TCP connection within 3.5 seconds from GitHub's runner

---

## 🧠 Smart Deduplication

Most collectors dedup on `host:port` only, which silently drops configs with different UUIDs on the same server. FastNodes deduplicates on the **full config identity**:

```
protocol + host + port + credential(UUID/password) + transport + security
```

This means if a server hosts multiple VLESS configurations (common with Xray setups), all of them are kept — exactly matching what you'd get subscribing to the source directly.

---

## 📊 Stats (typical run)

| Metric | Value |
|--------|-------|
| Sources fetched | 158 repositories |
| Raw lines processed | ~726,000 |
| CDN / blacklist filtered | ~123,000 |
| Unique proxies after dedup | ~100,000 |
| Alive after TCP check | ~52,000 |
| Countries covered | ~80 |
| Protocols | VLESS, Trojan, VMess, SS, Hysteria2, TUIC |
| Runtime | ~25 minutes |
| Update frequency | Every 6 hours |

---

## 🔄 Update Schedule

| UTC | Tehran (IRST) |
|-----|---------------|
| 00:00 | 03:30 |
| 06:00 | 09:30 |
| 12:00 | 15:30 |
| 18:00 | 21:30 |

You can also trigger a manual run from the [Actions tab](../../actions/workflows/collect.yml).

---

## 📂 Repository Structure

```
FastNodes/
├── .github/
│   └── workflows/
│       └── collect.yml              # Runs every 6h, drives everything
├── ProxyCollector/
│   ├── Collector/
│   │   └── ProxyCollector.cs        # Core engine — fetch, parse, score, output
│   ├── Configuration/
│   │   └── CollectorConfig.cs       # Reads source URLs from env vars
│   ├── Services/
│   │   └── IPToCountryResolver.cs   # GeoIP lookup (city → country → DNS fallback)
│   ├── Models/
│   │   ├── CityInfo.cs
│   │   └── CountryInfo.cs
│   ├── GeoLite2-City.mmdb           # Auto-downloaded each run (P3TERX mirror)
│   ├── GeoLite2-Country.mmdb        # Auto-downloaded each run
│   └── blacklist.netset             # FireHOL Level 1 (auto-downloaded each run)
└── sub/
    ├── everything.txt               # All alive proxies, quality-sorted (no size cap)
    ├── protocols/                   # Per-protocol: .txt (all) + .yaml (top 1000)
    │   ├── vless.txt / vless.yaml
    │   ├── trojan.txt / trojan.yaml
    │   ├── vmess.txt / vmess.yaml
    │   ├── ss.txt / ss.yaml
    │   └── hysteria2.txt / hysteria2.yaml
    ├── countries/                   # Per-country: .txt (all) + .yaml (top 1000)
    │   ├── IR.txt / IR.yaml         # Iran
    │   ├── DE.txt / DE.yaml         # Germany
    │   └── ... (~80 countries)
    └── continents/                  # Per-continent: .txt (all) + .yaml (top 1000)
        ├── Europe.txt / Europe.yaml
        ├── Asia.txt / Asia.yaml
        ├── NorthAmerica.txt / NorthAmerica.yaml
        ├── SouthAmerica.txt / SouthAmerica.yaml
        ├── Africa.txt / Africa.yaml
        └── Oceania.txt / Oceania.yaml
```

---

## ⚠️ Honest Notes

**About testing from GitHub servers:**  
The TCP alive check runs from GitHub Actions (Azure, US/EU regions). A node that passes TCP from there might still be blocked inside Iran, and some Iran-friendly nodes may appear dead to the checker. This is a fundamental limitation of any cloud-based collector. The quality score mitigates this by ranking well-configured nodes first — a VLESS+REALITY node with a valid UUID and proper SNI is very likely to actually work, regardless of where it was checked.

**This project does not:**
- Host or operate any proxy servers
- Guarantee any node works in your specific location or ISP
- Collect any user data whatsoever

All configs are sourced from publicly available GitHub repositories. Credit goes to all the original collectors and server operators.

---

## 🙏 Sources

FastNodes aggregates from 150+ public repositories. Major contributors include: AvenCores, MatinGhanbari, barry-far, Epodonios, Surfboardv2ray, 10ium, NiREvil, F0rc3Run, soroushmirzaei, wuqb2i4f, V2RayRoot, sevcator, igareck, youfoundamin, HosseinKoofi, Argh94, Mahdi0024, liketolivefree, lagzian, MahsaNetConfigTopic, hamedcode, AzadNetCH, Leon406, roosterkid, ebrasha, Danialsamadi, LalatinaHub, Farid-Karimi, and many others.

---

<div align="center">

**If FastNodes helps you, a ⭐ means a lot**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:24243e,50:302b63,100:0f0c29&height=120&section=footer" width="100%"/>

*Auto-updated every 6 hours · Built with C# .NET 9 · Powered by GitHub Actions*
