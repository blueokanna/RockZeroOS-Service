<p align="center">
  <img src="RockZero.png" alt="RockZeroOS Logo" width="200"/>
</p>

<h1 align="center">RockZeroOS</h1>

<p align="center">
  <strong>Secure Private Cloud NAS Operating System</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust"></a>
  <a href="https://flutter.dev/"><img src="https://img.shields.io/badge/flutter-3.19%2B-blue.svg" alt="Flutter"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/build-passing-brightgreen.svg" alt="Build Status">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a>
</p>

---

## Overview

RockZeroOS is a high-performance, secure cross-platform private cloud NAS operating system. The backend is built entirely in Rust using Actix-web with WPA3-SAE key exchange, EdDSA (Ed25519) JWT authentication, ChaCha20-Poly1305 secure HLS transport encryption, and BLAKE3-based key derivation and integrity tooling. The frontend is a Flutter cross-platform client supporting Android, iOS, Windows, macOS, Linux, and Web, with Material Design 3 UI optimized for low-power ARM SoCs (Snapdragon 835 class).

## Features

- **Dashboard** — System overview with CPU, memory, disk, network monitoring, and chronograph-style speed test
- **File Manager** — Browse disks, navigate directories, upload/download files, LAN file transfer, WebDAV, network shares
- **Video Playback** — SAE-protected HLS streaming with session-based authentication, ChaCha20-Poly1305 transport encryption (PMK → HKDF-BLAKE3 → session key), local Flutter proxy playback, proof-ticket / ZKP protected segment access, codec-aware adaptive timeouts (30s H.264/120s AV1), on-demand seek segment generation for VP9/AV1 transcode, and PTS timestamp normalization (`-fflags +genpts+discardcorrupt -avoid_negative_ts make_zero`)
- **Game Center** — Multi-platform gaming hub with Steam, Epic Games, WeGame, Ubisoft Connect, Xbox native store integration (no WebView), unified game library, daily Top 30 recommendations, and built-in SteamDB viewer
- **Localization & Motion** — zh-CN / English app-level localization foundation, low-motion route transitions, and reduced heavy list animations for weaker Android, Windows, and Linux devices
- **WASM Runtime** — Run WebAssembly applications and scripts via Wasmtime, including built-in SteamDB viewer (name + AppID dual search), M3U8 video downloader (custom save directory), and Steam P2P connection analyzer (with NAT type help docs)
- **Storage Management** — Linux full disk lifecycle management (format/mount/partition/SMART/secure erase) and Windows scoped single-root file management with disk status visibility
- **Hardware Transcoding** — Auto-detected FFmpeg hardware acceleration (VAAPI, V4L2 M2M, Rockchip MPP)
- **Security** — FIDO2/WebAuthn, wallpaper customization with glassmorphic blur (BackdropFilter high-contrast frost), dynamic color (80% wallpaper + 20% system), Reed-Solomon + CRC32 secure storage, Bulletproofs ZKP for authentication
- **MD3 Expressive Components** — Custom loading indicators (starburst spinner, wavy progress, pulsing dots, segmented spinner), secure connection shield animation for SAE handshake, buffering overlay with rotating dot ring
- **Edge-to-Edge UI** — Full-screen gesture navigation support on Android, transparent system bars, predictive back gestures

## Security Architecture

```mermaid
flowchart TB
    subgraph Client["Flutter Client"]
        A[User Login] --> B[EdDSA JWT Auth]
        B --> C[SAE Handshake]
        C --> D[Session Auth]
    end
    
    subgraph Server["Rust Backend"]
        E[JWT Verification] --> F[SAE Key Exchange]
        F --> G[PMK Derivation]
      G --> H[ChaCha20-Poly1305 Transport]
    end
    
    B --> E
    C --> F
    D --> H
    
    style Client fill:#e1f5fe
    style Server fill:#fff3e0
```

| Feature | Technology | Description |
|---------|------------|-------------|
| JWT Authentication | EdDSA (Ed25519) | Private key derived from BLAKE3 hash of password |
| Key Exchange | WPA3-SAE (Dragonfly) | Secure key negotiation based on Curve25519 |
| Video Transport Encryption | ChaCha20-Poly1305 | Session-derived secure HLS segment transport |
| HLS Cache Protection | Optional at-rest segment encryption | Non-Windows default: enabled; Windows default: disabled for stable playback |
| Session Auth | 128-bit UUID + BLAKE3 HMAC | Session-bound playback token and proof-ticket chain |
| Replay Protection | Timestamp + Nonce + HMAC | Multi-layer protection mechanism |
| Zero-Knowledge Proof | Bulletproofs RangeProof | Prove password knowledge without revealing it (auth only) |
| Hardware Auth | FIDO2/WebAuthn | Support for YubiKey, TouchID, FaceID |
| Secure Storage | Reed-Solomon + CRC32 | Data integrity verification and error correction |

## Video Playback Architecture

RockZeroOS uses SAE-protected HLS streaming for all video playback. The client performs an SAE handshake, creates a secure HLS session with `direct_mode: false`, serves playback through a local Flutter proxy, and uses session-bound proof tickets or ZKP material for segment access. Segment transport is ChaCha20-Poly1305 encrypted with a session key derived from PMK via HKDF-BLAKE3.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    
    C->>S: 1. JWT Authentication (EdDSA)
    S-->>C: Access Token
    
    C->>S: 2. SAE Init
    S-->>C: Temp Session ID
    
    C->>S: 3. SAE Commit (Curve25519)
    S-->>C: Server Commit
    
    C->>S: 4. SAE Confirm
    S-->>C: Server Confirm + PMK
    
    C->>S: 5. Create HLS Session (direct_mode=false)
    S-->>C: Session ID + Playlist URL
    C->>C: 6. Start local secure HLS proxy
    C->>S: 7. GET playlist.m3u8
    S-->>C: M3U8 playlist
    
    loop Each Video Segment
      C->>S: 8. POST segment_N.ts with proof ticket / ZKP
      Note over S: Verify session + proof ticket / ZKP
        Note over S: Stream copy ≤1080p / HW transcode >1080p
      S-->>C: ChaCha20-Poly1305 encrypted segment
      Note over C: Proxy decrypts and forwards TS bytes to player
    end
```

### Client-side Hardware Decoding

The Flutter client uses media_kit (libmpv) with hardware decoding enabled by default. The `Video()` widget is wrapped in `SizedBox.expand()` to ensure proper sizing on all platforms. mpv is configured with:

- `hwdec=auto-safe` — Automatically selects the best available hardware decoder
- `rebase-start-time=yes` — Rebases stream start time to zero (fixes MKV files with non-zero PTS offset showing e.g. 26:28:10 instead of 00:00:00)
- `demuxer-lavf-o=fflags=+genpts+discardcorrupt` — Regenerates presentation timestamps and discards corrupt frames
- `cache=yes` with `demuxer-max-bytes=50MiB` / `demuxer-max-back-bytes=25MiB` — Reduces stalls
- `stream-buffer-size=2MiB` — Optimized for network streaming

| Platform | API | Configuration |
|----------|-----|---------------|
| Android | MediaCodec | `hwdec=mediacodec` via libmpv |
| iOS | VideoToolbox | `hwdec=videotoolbox` via libmpv |
| Windows/Linux/macOS | Auto-detect | `hwdec=auto-safe` via libmpv |

### Audio Playback

Audio uses `just_audio` with a **triple-fallback source strategy**:

1. `LockCachingAudioSource` — Progressive download with caching (20s timeout)
2. `AudioSource.uri` with Auth headers — Direct streaming (20s timeout)
3. `setUrl` — Simple URL playback (20s timeout)

Unsupported audio codecs (wmav1/2, wmapro, wmalossless, pcm_bluray/dvd, cook, ra_288, atrac3/3p, ape, etc.) are automatically transcoded to AAC/MP3 on the server side before streaming.

The **back button** on the full-screen audio player minimizes playback to the background mini player (transferring position, volume, speed, and loop state to the global `AudioPlayerService`), rather than stopping audio. A dedicated **stop button** is provided in the app bar for explicit playback termination.

### Key Derivation

```
PMK (from SAE handshake)
  → HKDF-BLAKE3(salt="hls-session-salt:{session_id}", info="hls-master-key")
  → 256-bit ChaCha20-Poly1305 transport key
```

Each segment is encrypted as: `nonce(12B) ‖ ChaCha20-Poly1305(plaintext, key, nonce)`

## Storage Management

- **Smart Formatting** — Auto-select optimal filesystem based on usage
  - System boot: ext4
  - Media library: XFS (large file optimization)
  - Database: ext4 (journal optimization)
  - Backup: Btrfs (snapshot support)
  - Cross-platform: exFAT/NTFS
- **Auto Mount** — Smart mount point generation with UUID/Label recognition
- **Partition Management** — GPT/MBR partition table creation
- **Disk Health** — SMART data monitoring, temperature detection
- **Secure Erase** — Multi-pass overwrite for data destruction

## Windows Scoped Storage Mode

Windows runs in a different production mode from Linux.

- RockZeroOS does **not** format, partition, wipe, or auto-mount disks on Windows.
- The backend exposes disk status and capacity information, but file operations are limited to **one explicitly selected storage root**.
- On first use, the Windows server must bind to **one folder on one Windows disk** before file browsing is enabled.
- The selected folder is persisted in `DATA_DIR/storage/windows-storage-root.json`.
- Flutter clients on Windows and Android use the same backend scope endpoints, so the selected root is enforced consistently across frontend platforms.
- Windows secure HLS playback uses the same scoped root guard and is verified by the Flutter smoke chain (`secure_hls_playlist_only_smoke_test.dart` and `secure_hls_smoke_test.dart`).
- `ROCKZERO_HLS_CACHE_AT_REST_ENCRYPTION` defaults to `false` on Windows and `true` on non-Windows builds. This keeps Windows playback stable while preserving at-rest protection by default on Linux/macOS.

### First Windows Startup Flow

1. Open the Files page.
2. If the backend is running on Windows and no storage root has been selected yet, the client enters **Storage Setup** instead of showing all disks.
3. Browse the server-side Windows drive list and choose exactly one folder.
4. Confirm the folder. RockZeroOS writes the scope binding and initializes managed subdirectories (`videos`, `temp`, `cache/hls`, `logs`).
5. After that, all file operations are restricted to that root and its subdirectories only.

### Supported Windows File Operations

- Browse directories inside the selected root
- Upload and download files
- Create directories
- Rename files and folders
- Copy and move files and folders
- Delete files and folders
- Preview text files
- Save inline edits for supported text files
- Stream media and read disk/storage status

### Windows Scope API

- `GET /api/v1/filemanager/scope/status` — Returns whether Windows storage has already been bound
- `GET /api/v1/filemanager/scope/browse` — Returns server-side drives or subdirectories for setup browsing
- `POST /api/v1/filemanager/scope/configure` — Persists the selected Windows storage root
- `POST /api/v1/filemanager/text/save` — Saves supported text-file edits inside the scoped root

Any request outside the selected Windows root is rejected by the backend path guard.

## Hardware Accelerated Transcoding

The server auto-detects available hardware at startup and selects the optimal encoding pipeline. On ARM architectures, VAAPI is **explicitly skipped** (Mali/Panfrost GPUs expose `/dev/dri/renderD128` but do not support video encoding), and the detection order is: **Rockchip MPP → V4L2 M2M → Software fallback**. A test encode is performed to verify each candidate actually works before committing to it.

| Platform | Detection Method | Encoder | Decoder | Notes |
|----------|-----------------|---------|---------|-------|
| Intel | VAAPI device + vendor ID `0x8086` | h264_vaapi | hwaccel vaapi | Verified via FFmpeg test encode |
| AMD | VAAPI device + vendor ID `0x1002` | h264_vaapi | hwaccel vaapi | Verified via FFmpeg test encode |
| Rockchip (RK3588/RK3399) | `/proc/cpuinfo`, device tree | h264_rkmpp | rkmpp | Requires MPP libraries; priority 1 on ARM |
| Amlogic (A311D/S905/S922) | `/proc/cpuinfo`, device tree, `/dev/amvideo` | h264_v4l2m2m | meson_vdec | Falls back to software if V4L2 M2M fails |
| Generic ARM | `/dev/video10`, `/dev/video11` | h264_v4l2m2m | h264_v4l2m2m | Verified via encode test; priority 2 on ARM |
| Fallback | — | libx264 (ultrafast) | software | Used when no hardware is detected |

For ≤1080p content, the server uses stream copy (`-c:v copy -c:a copy -map 0:v? -map 0:a?`) which is near-instant. The `-map 0:v? -map 0:a?` flags ensure only video and audio streams are selected, avoiding mpegts muxer failures from subtitle or data tracks. All ffmpeg invocations include `-fflags +genpts+discardcorrupt` (input) and `-avoid_negative_ts make_zero` (output) to normalize PTS timestamps — this ensures MKV files with non-zero start times (e.g. 26:28:10) produce HLS segments starting from 00:00:00.

**Codec-aware timeouts**: Before spawning ffmpeg, the server probes the video codec via ffprobe. H.264/HEVC videos get a 30-second first-segment timeout (stream copy is fast). AV1/VP9/other codecs get 120 seconds since software transcode is slower.

**On-demand seek**: When a player seeks to a distant segment during transcode (>5 segments ahead of current progress), the server generates the requested segment on-demand using `-ss` + hardware/software encode, bypassing the need to wait for all preceding segments. The on-demand segment uses the same ChaCha20-Poly1305 cache protection path as the rest of the secure HLS cache when at-rest cache encryption is enabled.

**HLS cache defaults**: Max 1 GB HLS cache, 1-day retention, 5-minute idle cleanup interval. Auto-cleanup triggers when total cache exceeds 1 GB threshold.

**Windows playback note**: temporary HLS cache at-rest encryption is disabled by default on Windows. Transport encryption for served segments remains enabled. If you explicitly want encrypted temporary cache files on Windows, set `ROCKZERO_HLS_CACHE_AT_REST_ENCRYPTION=true` and validate playback in your environment.

**Windows diagnostics**: use `scripts/secure_hls_playlist_only_diag.ps1` to reproduce playlist-only failures. When ProcDump and `minidump-stackwalk` are available, the script writes `summary.json`, `procdump.stackwalk.txt`, `procdump.stackwalk.summary.txt`, and `suspicious_threads.json` under `storage/smoke/playlist_only_diag/<timestamp>/`.

### Adaptive Hybrid Transport (UDP/TCP)

RockZeroOS uses an adaptive hybrid transport layer for secure media delivery. The runtime policy is now constrained to the following production bounds:

- **Default ratio**: UDP 70% + TCP 30%
- **Maximum UDP ratio**: 70% (therefore TCP minimum is 30%)
- **Maximum TCP ratio**: 90% (therefore UDP minimum is 10%)
- **Adaptive trigger**: UDP loss rate above threshold reduces UDP share and increases TCP reliability

The transport startup profile is tuned for high-throughput devices (including ARM NAS boards):

- `chunk_size`: 128 KiB
- `udp_window_size`: 96
- `send_buffer_size`: 16 MiB
- `tcp_max_retries`: 5
- `udp_loss_threshold`: 3%

On Amlogic A311D class devices, hardware path preference remains:

1. Stream copy when source codec/container is directly playable (fastest path, no quality loss)
2. Hardware encode/transcode via `h264_v4l2m2m` when re-encode is required
3. Software fallback (`libx264`) only when hardware encoder validation fails

This design keeps startup latency low while retaining playback continuity under packet loss.

## Game Center

Multi-platform gaming hub with **fully native** UI integration (no WebView). Each platform tab fetches **real-time data from official APIs** with built-in catalog fallback:

| Platform | Official API Source | Features |
|----------|---------------------|----------|
| Steam | Steam Web API (`store.steampowered.com`) | Game library, play time stats, profile, API key binding, SteamDB viewer |
| Epic Games | Epic GraphQL API (`graphql.epicgames.com`) | Live catalog, free game highlights, featured carousel, category browsing, search |
| WeGame | WeGame Internal API (`wegame.com.cn/api/v1/`) | Live catalog, hot games ranking, featured carousel, search, save to library |
| Ubisoft Connect | Ubisoft Store API (`store.ubisoft.com`) + Ubisoft Services API | Live catalog, featured carousel, category browsing, search, save to library |
| Xbox | Game Pass Catalog (`catalog.gamepass.com`) + Microsoft DisplayCatalog API | Live catalog, Game Pass highlights, featured carousel, search, save to library |

- All platform tabs show a **live data indicator** (🔴 实时) when displaying API-fetched data
- Game cover images are loaded directly from official CDN URLs (Epic `cdn1.epicgames.com`, Ubisoft `staticctf.ubisoft.com`, Xbox `store-images.s-microsoft.com`)
- **Built-in catalog images**: 25+ hardcoded games use Steam CDN (`cdn.akamai.steamstatic.com/steam/apps/{appid}/header.jpg`) for instant image display without API calls
- 30-minute server-side cache with automatic refresh on pull-to-refresh
- Graceful degradation: if any API is unreachable, the tab seamlessly falls back to curated catalog data

The **My Library** tab provides a unified view of game accounts across all platforms with Steam full library integration (game count, total play time, recently played).

The **Daily Top 30** tab shows curated recommendations with 30 games per platform (Steam, Epic, WASM) scored by recency, price, and availability.

### Built-in WASM Applications

| App | Description |
|-----|-------------|
| SteamDB Viewer | Query Steam API for game details by **name search** (Steam Store storesearch + suggest fallback) or AppID: price, online players, reviews, DLC, system requirements |
| M3U8 Downloader | Parse M3U8 playlists, download TS segments, auto-merge with AES decryption support. Supports **custom save directory** (NAS default / Downloads / custom path) with path sanitization and security checks |
| Steam P2P Info | View Steam player profiles, friends list, recent games, and P2P connection details. Includes **collapsible help documentation** with NAT type explanations (Open/Moderate/Strict) and troubleshooting guide |

## Dynamic Theming & Wallpaper

RockZeroOS supports advanced dynamic theming:

- **Material You** — Seed color from user preference or system accent color
- **Custom Wallpaper** — Set custom wallpaper from gallery; dominant color extracted for theme blending
- **Dynamic Color Blending** — 80% custom wallpaper color + 20% system accent color
- **Glassmorphic Cards** — When wallpaper is active, all cards use frosted glass effect with `BackdropFilter` blur (sigma 20), semi-transparent backgrounds, and subtle border highlighting
- **Edge-to-Edge** — Transparent status bar and navigation bar on Android with predictive back gesture support

## Project Structure

```mermaid
graph LR
    subgraph Backend["Rust Backend"]
        A[rockzero-common] --> B[rockzero-crypto]
        B --> C[rockzero-sae]
        B --> D[rockzero-media]
        B --> E[rockzero-db]
        C --> F[rockzero-service]
        D --> F
        E --> F
    end
    
    subgraph Frontend["Flutter Frontend"]
        G[RockZeroOS-UI]
    end
    
    F <--> G
    
    style Backend fill:#ffebee
    style Frontend fill:#e8f5e9
```

```
RockZeroOS-Service/
├── rockzero-common/              # Common library (error handling, config, types)
├── rockzero-crypto/              # Cryptography library
│   ├── src/
│   │   ├── jwt.rs                # EdDSA JWT (Ed25519 + BLAKE3)
│   │   ├── ed25519.rs            # Ed25519 signature operations
│   │   ├── bulletproofs_ffi.rs   # Bulletproofs RangeProof FFI
│   │   ├── zkp.rs                # ZKP authentication logic
│   │   ├── aes.rs                # AES helpers for non-HLS crypto paths
│   │   ├── hash.rs               # BLAKE3, SHA3-256 hashing
│   │   ├── signature.rs          # Digital signatures
│   │   ├── tls.rs                # Rustls TLS configuration
│   │   └── utils.rs              # Crypto utilities
├── rockzero-sae/                 # WPA3-SAE key exchange
│   ├── src/
│   │   ├── client.rs             # SAE client (Curve25519)
│   │   ├── server.rs             # SAE server
│   │   ├── crypto.rs             # Dragonfly key exchange
│   │   ├── key_derivation.rs     # PMK derivation via HKDF
│   │   ├── protocol.rs           # SAE protocol state machine
│   │   └── types.rs              # SAE message types
├── rockzero-media/               # Media processing
│   ├── src/
│   │   ├── session.rs            # HLS session management
│   │   ├── encryptor.rs          # Media encryption helpers and cache protection
│   │   ├── bulletproof_auth.rs   # Per-segment authentication
│   │   ├── media_processor.rs    # FFmpeg detection & HW capabilities
│   │   ├── chunk_manager.rs      # Progressive chunk management
│   │   ├── playlist.rs           # M3U8 playlist generation
│   │   ├── tcp_stream.rs         # TCP streaming transport
│   │   ├── udp_stream.rs         # UDP streaming transport
│   │   └── secure_transport.rs   # Encrypted transport layer
├── rockzero-db/                  # Database (SQLite + Reed-Solomon)
│   ├── src/
│   │   ├── secure_db.rs          # Encrypted database operations
│   │   ├── operations.rs         # CRUD operations
│   │   └── models.rs             # Database models
├── rockzero-service/             # Main HTTP service (Actix-web)
│   ├── src/
│   │   ├── main.rs               # Server startup, route configuration
│   │   ├── middleware.rs          # JWT auth middleware
│   │   ├── storage_manager.rs    # Disk & mount management
│   │   ├── fido.rs               # FIDO2/WebAuthn handler
│   │   ├── handlers/
│   │   │   ├── auth.rs           # User registration & login (EdDSA JWT)
│   │   │   ├── zkp_auth.rs       # Bulletproofs ZKP authentication
│   │   │   ├── secure_hls.rs     # SAE handshake + encrypted HLS streaming
│   │   │   ├── streaming.rs      # Media info, thumbnails, HLS playlist, audio transcode
│   │   │   ├── filemanager.rs    # File CRUD, upload, download
│   │   │   ├── storage.rs        # Storage overview & disk info
│   │   │   ├── storage_management.rs  # Format, mount, unmount, erase
│   │   │   ├── disk_manager.rs   # Disk detail & SMART
│   │   │   ├── appstore.rs       # WASM app registry
│   │   │   ├── wasm_store.rs     # WASM app store & game APIs
│   │   │   ├── system.rs         # System info (CPU, mem, temp)
│   │   │   ├── speedtest.rs      # Network speed test
│   │   │   ├── lan_transfer.rs   # LAN file transfer
│   │   │   ├── webdav.rs         # WebDAV server
│   │   │   ├── widgets.rs        # Dashboard widgets
│   │   │   └── health.rs         # Health check endpoint
└── RockZeroOS-UI/                # Flutter cross-platform client
    └── lib/
        ├── core/
        │   ├── models/           # API models (DiskInfo, etc.)
        │   ├── network/          # API service, Dio HTTP client
        │   ├── services/         # Wallpaper, media_kit init, dynamic color
        │   ├── theme/            # M3 theme, dynamic color, animation curves
        │   └── widgets/          # ShellScaffold, WallpaperBackground, GlassmorphicBackground, DynamicColorCard
        ├── features/
        │   ├── auth/             # Login, register pages (glassmorphic cards)
        │   ├── dashboard/        # Dashboard, speed test
        │   ├── files/            # File browser, video player
        │   │   └── presentation/pages/
        │   │       ├── files_page.dart             # Disk grid + file listing
        │   │       └── secure_hls_video_player.dart # SAE+HLS video player
        │   ├── appstore/         # Game center
        │   │   └── presentation/
        │   │       ├── pages/
        │   │       │   └── wasm_store_page.dart     # Multi-platform game hub
        │   │       └── widgets/
        │   │           └── platform_game_tab.dart   # Native game tabs (Epic/WeGame/Ubisoft/Xbox)
        │   ├── device_discovery/ # mDNS device discovery
        │   ├── disk/             # Disk formatting & management
        │   ├── storage/          # Storage overview
        │   ├── system/           # System monitoring
        │   └── settings/         # App settings, wallpaper, blur
        └── services/
            ├── sae_client_curve25519.dart    # SAE Dragonfly client
            └── sae_handshake_service.dart    # SAE handshake orchestration
```

## Quick Start

### Prerequisites

- Rust 1.75+ (edition 2021)
- FFmpeg 6.0+ (bundled for ARM64, or system-installed)
- SQLite 3.x
- Flutter 3.19+ with Dart 3.3+

### Build Backend

```bash
git clone https://github.com/blueokanna/rockzero-service.git
cd rockzero-service

cargo build --workspace --release
cargo test --workspace
cargo run -p rockzero-service --release
```

### Configuration

Create `.env` file:

```env
HOST=0.0.0.0
PORT=8080
RUST_LOG=info

DATA_DIR=./data
DATABASE_URL=./data/rockzero.db

JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION_HOURS=24
REFRESH_TOKEN_EXPIRATION_DAYS=7

STORAGE_ROOT=/mnt/storage
MAX_UPLOAD_SIZE=10737418240
HLS_CACHE_PATH=./data/hls_cache
```

### Run Flutter Client

```bash
cd RockZeroOS-UI
flutter pub get
flutter run
```

## API Reference

### Authentication

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    
    C->>S: POST /api/v1/auth/register
    Note right of S: Create user with<br/>EdDSA JWT + ZKP registration
    S-->>C: {tokens, user}
    
    C->>S: POST /api/v1/auth/login
    Note right of S: Verify password<br/>Generate EdDSA JWT
    S-->>C: {tokens, user}
    
    C->>S: POST /api/v1/auth/zkp/login
    Note right of S: Verify Bulletproofs<br/>RangeProof
    S-->>C: {tokens, user}
```

### Secure HLS (SAE + ChaCha20-Poly1305)

```http
POST /api/v1/secure-hls/sae/init
POST /api/v1/secure-hls/sae/commit
POST /api/v1/secure-hls/sae/confirm
POST /api/v1/secure-hls/session/create
GET  /api/v1/secure-hls/{session_id}/playlist.m3u8
GET  /api/v1/secure-hls/{session_id}/segment_{n}.ts
```

### Media Info & Streaming Utilities

```http
GET  /api/v1/streaming/formats             # Supported media formats
GET  /api/v1/streaming/library             # List media library
GET  /api/v1/streaming/info/{path}         # Get media info (codecs, duration, resolution)
GET  /api/v1/streaming/extended-info/{path} # Extended media info (EXIF, tracks)
GET  /api/v1/streaming/hls/{path}          # Generate HLS playlist
GET  /api/v1/streaming/thumbnail/{path}    # Get video thumbnail
GET  /api/v1/streaming/transcode/{path}    # Audio transcoding
```

### File Manager

```http
GET    /api/v1/filemanager/list?path=...
POST   /api/v1/filemanager/upload
GET    /api/v1/filemanager/download?path=...
GET    /api/v1/filemanager/media/info?path=...
GET    /api/v1/filemanager/media/image?path=...
GET    /api/v1/filemanager/media/thumbnail?path=...
DELETE /api/v1/filemanager/delete
```

### ZKP (Auth only)

```http
POST /api/v1/zkp/search/token
POST /api/v1/zkp/search/execute
POST /api/v1/zkp/share/proof
POST /api/v1/zkp/share/verify
POST /api/v1/zkp/proof/generate
```

### WASM Store & Game Center

```http
GET  /api/v1/wasm-store/overview                     # Store overview (stats, categories)
GET  /api/v1/wasm-store/steam/featured               # Steam featured games
GET  /api/v1/wasm-store/steam/app/{app_id}            # Steam app details
GET  /api/v1/wasm-store/steam/library                 # User's Steam library
GET  /api/v1/wasm-store/steam/player                  # Steam player summary
GET  /api/v1/wasm-store/steam/search?q=...            # Search Steam store
GET  /api/v1/wasm-store/epic/free                     # Epic free games (GraphQL)
GET  /api/v1/wasm-store/platform/games?platform=epic|wegame|ubisoft|xbox  # Official platform API data
GET  /api/v1/wasm-store/search?q=...                  # Search WASM apps
GET  /api/v1/wasm-store/recommendations               # Daily Top 30 recommendations
POST /api/v1/wasm-store/github/import                 # Import WASM from GitHub
POST /api/v1/wasm-store/wasm/run-script               # Execute WASM script
GET  /api/v1/wasm-store/wasm/apps                     # List installed WASM apps
GET  /api/v1/wasm-store/wasm/apps/{app_id}            # WASM app details
POST /api/v1/wasm-store/wasm/install                  # Install WASM app
POST /api/v1/wasm-store/wasm/{app_id}/run             # Run installed WASM app
DELETE /api/v1/wasm-store/wasm/{app_id}               # Uninstall WASM app
GET  /api/v1/wasm-store/builtin/{app_id}/run          # Run built-in app (SteamDB/M3U8/P2P)
POST /api/v1/wasm-store/builtin/m3u8-downloader/download  # Download M3U8 video
GET  /api/v1/wasm-store/builtin/downloads             # List downloaded files
GET  /api/v1/wasm-store/builtin/downloads/{filename}  # Serve downloaded file
```

### Storage

```http
GET  /api/v1/storage/disks
GET  /api/v1/storage/disk/{name}
POST /api/v1/storage/format
POST /api/v1/storage/mount
POST /api/v1/storage/unmount
POST /api/v1/storage/file                            # Write file to storage
```

### Storage Management

```http
GET  /api/v1/storage-management/overview             # Storage overview
POST /api/v1/storage-management/format               # Format disk
POST /api/v1/storage-management/mount                 # Mount filesystem
POST /api/v1/storage-management/unmount               # Unmount filesystem
POST /api/v1/storage-management/secure-erase          # Secure erase disk
GET  /api/v1/storage-management/smart/{device}        # SMART health data
POST /api/v1/storage-management/partition              # Create partition
POST /api/v1/storage-management/scan                  # Scan for new devices
```

### System

```http
GET  /api/v1/system/info                             # System overview
GET  /api/v1/system/cpu                              # CPU details
GET  /api/v1/system/memory                           # Memory usage
GET  /api/v1/system/disks                            # Disk info
GET  /api/v1/system/usb                              # USB devices
GET  /api/v1/system/hardware                         # Hardware info
GET  /api/v1/system/all                              # All system info combined
```

### Speed Test

```http
GET  /api/v1/speedtest/download                      # Download speed test
POST /api/v1/speedtest/upload                        # Upload speed test
GET  /api/v1/speedtest/ping                          # Latency test
GET  /api/v1/speedtest/info                          # Server info
```

### Invite System

```http
POST /api/v1/invite/create                           # Create invite code
GET  /api/v1/invite/validate/{code}                  # Validate invite
POST /api/v1/invite/remaining                        # Check remaining time
```

## Performance

| Operation | Performance | Notes |
|-----------|-------------|-------|
| EdDSA JWT Sign | ~0.1ms | Ed25519 via dalek |
| EdDSA JWT Verify | ~0.2ms | Ed25519 via dalek |
| SAE Handshake (full) | ~5-10ms | Curve25519 Dragonfly |
| Bulletproofs RangeProof | ~50ms | 64-bit range proof (auth only, not video playback) |
| ChaCha20-Poly1305 Encrypt/Decrypt | ~500 MB/s | Secure HLS transport and optional cache protection |
| BLAKE3 Hash | ~1 GB/s | Used for HKDF, HMAC, signatures |
| HLS Segment (stream copy) | <100ms | ≤1080p, no re-encoding |
| HLS Segment (hw transcode) | ~200-500ms | >1080p, VAAPI/V4L2 |
| HLS Segment (sw transcode) | ~1-3s | >1080p, libx264 ultrafast |
| On-demand seek (hw) | ~0.5-2s | Single segment via `-ss` + hw encode |
| On-demand seek (sw) | ~2-5s | Single segment via `-ss` + libx264 ultrafast |

## Roadmap

- [x] EdDSA (Ed25519) JWT authentication
- [x] WPA3-SAE key exchange (Curve25519 Dragonfly)
- [x] Bulletproofs RangeProof ZKP (authentication only)
- [x] SAE session-authenticated HLS streaming with ChaCha20-Poly1305 transport encryption
- [x] FIDO2/WebAuthn hardware authentication
- [x] Professional storage management
- [x] Hardware accelerated video transcoding (VAAPI / Rockchip MPP / V4L2 M2M)
- [x] ARM architecture-aware encoder detection (skip VAAPI on Mali/Panfrost)
- [x] Flutter cross-platform client with hardware-accelerated playback
- [x] Multi-platform native game center with official API integration (Steam/Epic/WeGame/Ubisoft/Xbox)
- [x] Triple-fallback audio playback with automatic server-side codec transcoding
- [x] LAN file transfer
- [x] WebDAV server
- [x] WASM application runtime (with built-in SteamDB viewer, M3U8 downloader, Steam P2P info)
- [x] Dynamic theming with wallpaper color extraction & glassmorphic UI
- [x] Edge-to-edge UI with gesture navigation
- [x] MD3 Expressive loading indicators (starburst spinner, wavy progress, secure shield animation)
- [x] PTS timestamp normalization for MKV/non-zero start time sources
- [x] Audio player back-minimizes to mini player (no audio interruption on back press)
- [x] Network speed test (download/upload/ping with chronograph UI)
- [x] Invite system with expiring codes
- [ ] RAID support
- [ ] Snapshot and backup
- [ ] Multi-user permission management
- [ ] SMB/NFS file sharing
- [ ] Remote access (DDNS, VPN)
- [ ] AI smart album

## Dependencies

### Rust Backend

- [Actix Web](https://actix.rs/) — High-performance async web framework
- [Tokio](https://tokio.rs/) — Async runtime
- [SQLx](https://github.com/launchbadge/sqlx) — Async SQLite driver
- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) — Ed25519 signatures
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) — Curve25519 operations
- [bulletproofs](https://github.com/dalek-cryptography/bulletproofs) — Zero-knowledge proofs
- [blake3](https://github.com/BLAKE3-team/BLAKE3) — Fast cryptographic hashing
- [chacha20poly1305](https://github.com/RustCrypto/AEADs) — ChaCha20-Poly1305 transport encryption
- [Wasmtime](https://wasmtime.dev/) — WebAssembly runtime
- [Rustls](https://github.com/rustls/rustls) — TLS implementation
- [FFmpeg](https://ffmpeg.org/) — Media transcoding (external binary)

### Flutter Frontend

- [Riverpod](https://riverpod.dev/) — State management
- [go_router](https://pub.dev/packages/go_router) — Navigation
- [media_kit](https://github.com/media-kit/media-kit) — Video playback (mpv)
- [flutter_animate](https://pub.dev/packages/flutter_animate) — Animations
- [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage) — Secure credential storage

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See [LICENSE](LICENSE) for the full license text.

## Contact

- **Author**: blueokanna
- **Email**: blueokanna@gmail.com
- **GitHub**: [https://github.com/blueokanna/rockzero-service](https://github.com/blueokanna/rockzero-service)

---

<p align="center">
  <strong>Made with ❤️ by blueokanna</strong>
</p>

<p align="center">
  Powered by Rust 🦀 | Secured by EdDSA + SAE + ChaCha20-Poly1305 🔐 | Accelerated by Hardware 🚀
</p>
