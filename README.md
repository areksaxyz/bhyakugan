# BHYAKUGAN (ビャクガン) 👁️

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey)](https://github.com/areksaxyz/bhyakugan)

```text
   ▄▄▄▄    ██░ ██▓██   ██▓ ▄▄▄       ██ ▄█▀ █    ██   ▄████  ▄▄▄       ███▄    █
   ▓█████▄ ▓██░ ██▒▒██  ██▒▒████▄     ██▄█▒  ██  ▓██▒ ██▒ ▀█▒▒████▄     ██ ▀█   █
   ▒██▒ ▄██▒██▀▀██░ ▒██ ██░▒██  ▀█▄  ▓███▄░ ▓██  ▒██░▒██░▄▄▄░▒██  ▀█▄  ▓██  ▀█ ██▒
   ▒██░█▀  ░▓█ ░██  ░ ▐██▓░░██▄▄▄▄██ ▓██ █▄ ▓▓█  ░██░░▓█  ██▓░██▄▄▄▄██ ▓██▒  ▐▌██▒
   ░▓█  ▀█▓░▓█▒░██▓ ░ ██▒▓░ ▓█   ▓██▒▒██▒ █▄▒▒█████▓ ░▒▓███▀▒ ▓█   ▓██▒▒██░   ▓██░
   ░▒▓███▀▒ ▒ ░░▒░▒  ██▒▒▒  ▒▒   ▓▒█░▒ ▒▒ ▓▒░▒▓▒ ▒ ▒  ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒
   ▒░▒   ░  ▒ ░▒░ ░▓██ ░▒░   ▒   ▒▒ ░░ ░▒ ▒░░░▒░ ░ ░   ░   ░   ▒   ▒▒ ░░ ░░   ░ ▒░
   ░    ░  ░  ░░ ░▒ ▒ ░░    ░   ▒   ░ ░░ ░  ░░░ ░ ░ ░ ░   ░   ░   ▒      ░   ░ ░
   ░       ░  ░  ░░ ░           ░  ░░  ░      ░           ░       ░  ░         ░
   ░         ░ ░
```

**Bhyakugan** adalah framework pemindaian backend otomatis berkecepatan tinggi yang dirancang khusus untuk Bug Bounty Hunter dan Security Researcher. Versi **3.7** menghadirkan stabilitas tinggi dengan engine **Anti-Stuck**, pencarian subdomain **Inkremental**, dan integrasi payload dari **PayloadsAllTheThings**.

## 🔥 Fitur Unggulan (v3.7)

### 🚀 Advanced Recon (Consistent & Aggressive)
*   **Incremental Discovery**: Menyimpan riwayat subdomain di `bhyakugan-output/`. Hasil pencarian tidak akan pernah berkurang antar sesi.
*   **Triple Threat Recon**: Menggabungkan `subfinder (-all)`, `assetfinder`, dan kueri langsung ke **crt.sh API**.
*   **httpx Optimized**: Filter host hidup dengan rate-limit dan timeout cerdas untuk mencegah hang pada infrastruktur besar.

### ✅ Enterprise-Grade Detection (Zero False Positive)
*   **SQL Injection**: Menggunakan **Strict Timing Check** (Baseline -> Payload -> Control) dengan payload terbaru (RLIKE, ELT, BENCHMARK).
*   **Isolated JS Analysis**: Engine analisis JavaScript sekarang berjalan secara terisolasi dengan *timeout* mandiri. Analisa file JS yang lambat tidak akan menahan proses pemindaian host.
*   **SSRF Evolution**: Deteksi metadata cloud (AWS, Azure, GCP, DigitalOcean, Oracle) dan bypass localhost tingkat lanjut.
*   **LFI & Wrapper**: Deteksi mendalam menggunakan PHP filter base64 dengan verifikasi konten otomatis untuk menghindari *Soft 404*.

## 🌐 Arsitektur (Workflow)

```mermaid
graph TD
    A[Input: Domain/URL] --> B{Mode Scan}
    
    subgraph "Phase 1: Incremental Recon"
    B -->|Wildcard| C[Load Subdomain History]
    C --> D[Parallel Discovery: Subfinder + Assetfinder + crt.sh]
    D --> E[Deduplication & Wildcard Cleaning]
    E --> F[Save Updated History]
    F --> G[httpx: Filtering Live Hosts]
    end
    
    subgraph "Phase 2: Core Scanning (Isolated)"
    B -->|Single Target| H[Scanner Engine]
    G --> H
    H --> I[Isolated Parallel Modules]
    
    I --> I1[Injections: SQLi, NoSQLi, SSRF, LFI]
    I --> I2[Logic: PP, Proxy, ORM Leak]
    I --> I3[Auth: JWT, SAML, GraphQL]
    I --> I4[Secrets: Validator Engine]
    I --> I5[JS: Isolated JSAnalyzer + Secrets Detect]
    end
    
    subgraph "Phase 3: Smart Reporting"
    I1 & I2 & I3 & I4 & I5 --> J[Deduplication Engine]
    J --> K[Grouped Findings (Root Cause)]
    K --> L[Final HTML Report]
    end
```

## 🛠️ Instalasi

### Prasyarat
*   Go 1.21+
*   Tools pendukung: `subfinder`, `assetfinder`, `httpx`

### Build dari Source
```bash
git clone https://github.com/areksaxyz/bhyakugan.git
cd bhyakugan
go build -o bhyakugan cmd/bhyakugan/main.go
```

## 📖 Penggunaan

### 1. Scan Wildcard (Consistent Mode)
Alat akan memuat data lama dan menambah temuan baru secara otomatis.
```bash
./bhyakugan -domain ugm.ac.id -depth 1
```

### 2. Scan Target Tunggal
```bash
./bhyakugan -target https://api.example.com -depth 2
```

### Opsi Flag
| Flag | Deskripsi |
| :--- | :--- |
| `-domain` | Domain utama untuk scan wildcard (Recon + Scan) |
| `-target` | URL spesifik untuk dipindai (Single Mode) |
| `-depth` | Kedalaman crawling (1 = page ini saja, 2+ = recursive) |
| `-payloads`| Path ke file wordlist kustom (Opsional) |
| `-timeout` | HTTP Timeout dalam detik (default: 10) |

## 🛡️ Modul Deteksi

| Kategori | Fitur Utama |
| :--- | :--- |
| **Injection** | SQLi (Advanced Time-Based), NoSQLi, SSRF (Cloud Meta), LFI (Wrappers) |
| **Logic** | Prototype Pollution, Proxy Misconfig, ORM Leak, SAML/JWT |
| **Recon** | Isolated JS Analysis, Subdomain History, S3 Bucket Verification |
| **Secrets** | Active Key Validation (OpenAI, AWS, GitHub, Stripe, dll) |

## ⚠️ Disclaimer
Bhyakugan dibuat untuk **Security Professionals**. Penggunaan tool ini untuk menyerang target tanpa izin tertulis adalah **ILEGAL**. Developer tidak bertanggung jawab atas penyalahgunaan tool ini.

---
Created with ❤️ by **areksaxyz (Muhamad Arga Reksapati)**
