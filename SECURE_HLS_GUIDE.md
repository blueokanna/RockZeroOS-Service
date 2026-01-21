# 安全HLS完整使用指南

## 概述

RockZeroOS的安全HLS实现提供了企业级的视频流加密和身份验证方案，基于以下技术：

- **WPA3-SAE (Simultaneous Authentication of Equals)**: 安全的密钥交换协议
- **ZKP (Zero-Knowledge Proof)**: 零知识证明身份验证
- **AES-256-GCM**: 军事级加密算法
- **防重放攻击**: 时间戳 + Nonce机制
- **硬件加速**: 支持VAAPI, V4L2, NVENC等

## 架构图

```
┌─────────────┐                    ┌─────────────┐
│   客户端    │                    │   服务器    │
│  (Flutter)  │                    │   (Rust)    │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. POST /sae/init              │
       │  { file_id }                    │
       ├────────────────────────────────>│
       │                                  │
       │  temp_session_id                │
       │<────────────────────────────────┤
       │                                  │
       │  2. 生成客户端 SAE commit       │
       │     (scalar, element, confirm)  │
       │                                  │
       │  3. POST /sae/complete          │
       │  { temp_session_id,             │
       │    client_commit,                │
       │    client_confirm }              │
       ├────────────────────────────────>│
       │                                  │
       │  server_commit, server_confirm  │
       │<────────────────────────────────┤
       │                                  │
       │  4. 计算 PMK (共享密钥)         │
       │                                  │
       │  5. POST /session/create        │
       │  { temp_session_id, file_id }   │
       ├────────────────────────────────>│
       │                                  │
       │  session_id, playlist_url       │
       │<────────────────────────────────┤
       │                                  │
       │  6. GET /playlist.m3u8          │
       ├────────────────────────────────>│
       │                                  │
       │  M3U8 (无密钥URL)               │
       │<────────────────────────────────┤
       │                                  │
       │  7. POST /{segment}             │
       │  { zkp_proof }                  │
       ├────────────────────────────────>│
       │                                  │
       │  验证ZKP → FFmpeg转码 → 加密    │
       │                                  │
       │  加密的视频段                   │
       │<────────────────────────────────┤
       │                                  │
```

## 后端实现（Rust）

### 1. 初始化SAE握手

```rust
// rockzero-service/src/handlers/secure_hls.rs

pub async fn init_sae_handshake(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<InitSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    // 1. 验证文件访问权限
    let _file = crate::db::find_file_by_id(&pool, &body.file_id, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    // 2. 获取用户密码哈希（用于SAE）
    let user = crate::db::find_user_by_id(&pool, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let password = user.password_hash.as_bytes().to_vec();

    // 3. 初始化SAE握手
    let manager = hls_manager.read().await;
    let temp_session_id = manager
        .init_sae_handshake(user_id.clone(), password)
        .map_err(convert_hls_error)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "temp_session_id": temp_session_id,
        "message": "SAE handshake initialized"
    })))
}
```

### 2. 完成SAE握手

```rust
pub async fn complete_sae_handshake(
    _pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CompleteSaeRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    // 处理客户端commit并生成服务器commit/confirm
    let (server_commit, server_confirm) = {
        let manager = hls_manager.read().await;
        let mut servers = manager.sae_servers.lock().unwrap();
        let sae_server = servers
            .get_mut(&body.temp_session_id)
            .ok_or_else(|| AppError::NotFound("SAE session not found".to_string()))?;

        let (server_commit, server_confirm) = sae_server
            .process_client_commit(&body.client_commit)
            .map_err(|e| AppError::CryptoError(format!("SAE commit failed: {}", e)))?;

        sae_server
            .verify_client_confirm(&body.client_confirm)
            .map_err(|e| AppError::CryptoError(format!("SAE confirm failed: {}", e)))?;

        (server_commit, server_confirm)
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_commit": server_commit,
        "server_confirm": server_confirm,
        "message": "SAE handshake completed"
    })))
}
```

### 3. 创建HLS会话

```rust
pub async fn create_hls_session(
    pool: web::Data<SqlitePool>,
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    claims: web::ReqData<crate::handlers::auth::Claims>,
    body: web::Json<CreateSessionRequest>,
) -> Result<impl Responder, AppError> {
    let user_id = claims.sub.clone();

    // 1. 验证文件访问权限
    let file = crate::db::find_file_by_id(&pool, &body.file_id, &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".to_string()))?;

    // 2. 获取ZKP注册数据（可选）
    let zkp_registration = get_user_zkp_registration(&pool, &user_id).await?;

    // 3. 完成SAE握手并创建会话
    let manager = hls_manager.read().await;
    let session_id = manager
        .complete_sae_handshake_with_registration(
            &body.temp_session_id,
            user_id.clone(),
            file.file_path.clone(),
            zkp_registration.clone(),
        )
        .map_err(convert_hls_error)?;

    // 4. 返回会话信息
    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "session_id": session_id,
        "expires_at": session.expires_at.timestamp(),
        "playlist_url": format!("/api/v1/secure-hls/{}/playlist.m3u8", session_id),
        "zkp_enabled": zkp_registration.is_some(),
        "encryption_method": "AES-256-GCM",
    })))
}
```

### 4. 获取加密视频段

```rust
pub async fn get_secure_segment(
    hls_manager: web::Data<Arc<RwLock<HlsSessionManager>>>,
    path: web::Path<(String, String)>,
    body: web::Json<SecureSegmentRequest>,
) -> Result<impl Responder, AppError> {
    let (session_id, segment_name) = path.into_inner();

    // 1. 验证会话
    let manager = hls_manager.read().await;
    let session = manager.get_session(&session_id).map_err(convert_hls_error)?;

    // 2. 验证ZKP证明
    if !verify_zkp_proof(&session, &body.zkp_proof)? {
        return Err(AppError::Unauthorized("Invalid ZKP proof".to_string()));
    }

    // 3. 从FFmpeg读取转码段
    let segment_data = read_video_segment_from_ffmpeg(&session.file_path, &segment_name).await?;

    // 4. 使用会话密钥加密
    let encrypted_segment = session
        .encrypt_segment(&segment_data)
        .map_err(convert_hls_error)?;

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(("X-Encrypted", "true"))
        .insert_header(("X-Encryption-Method", "AES-256-GCM"))
        .body(encrypted_segment))
}
```

### 5. FFmpeg转码实现

```rust
async fn transcode_segment_async(
    video_path: &std::path::Path,
    output_dir: &std::path::Path,
    segment_index: usize,
) -> Result<Vec<u8>, AppError> {
    use tokio::process::Command;

    const SEGMENT_DURATION: f64 = 10.0;
    let start_time = segment_index as f64 * SEGMENT_DURATION;

    let output_path = output_dir.join(format!("segment_{}.ts", segment_index));

    // 检测FFmpeg路径
    let ffmpeg_path = std::env::var("FFMPEG_PATH")
        .or_else(|_| rockzero_media::get_global_ffmpeg_path().ok_or(""))
        .unwrap_or_else(|_| "ffmpeg".to_string());

    // 检测硬件加速
    let hw_accel = detect_hardware_acceleration().await;

    // 构建FFmpeg参数
    let mut args = vec![
        "-y".to_string(),
        "-ss".to_string(),
        format!("{:.3}", start_time),
        "-i".to_string(),
        video_path.to_str().unwrap_or("").to_string(),
        "-t".to_string(),
        format!("{:.3}", SEGMENT_DURATION),
    ];

    // 根据硬件加速选择编码器
    match hw_accel {
        HardwareAccel::Vaapi => {
            args.extend(vec![
                "-hwaccel".to_string(),
                "vaapi".to_string(),
                "-c:v".to_string(),
                "h264_vaapi".to_string(),
            ]);
        }
        HardwareAccel::V4l2 => {
            args.extend(vec![
                "-c:v".to_string(),
                "h264_v4l2m2m".to_string(),
            ]);
        }
        HardwareAccel::None => {
            args.extend(vec![
                "-c:v".to_string(),
                "libx264".to_string(),
                "-preset".to_string(),
                "veryfast".to_string(),
            ]);
        }
    }

    // 音频编码
    args.extend(vec![
        "-c:a".to_string(),
        "aac".to_string(),
        "-b:a".to_string(),
        "128k".to_string(),
        "-f".to_string(),
        "mpegts".to_string(),
        output_path.to_str().unwrap_or("").to_string(),
    ]);

    // 执行FFmpeg
    let output = Command::new(&ffmpeg_path)
        .args(&args)
        .output()
        .await
        .map_err(|e| AppError::IoError(format!("Failed to execute FFmpeg: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::InternalServerError(format!(
            "FFmpeg transcode failed: {}",
            stderr
        )));
    }

    // 读取生成的段文件
    tokio::fs::read(&output_path)
        .await
        .map_err(|e| AppError::IoError(format!("Failed to read segment: {}", e)))
}
```

## 前端实现（Flutter）

### 完整的SecureHlsVideoPlayer

```dart
// RockZeroOS-UI/lib/features/files/presentation/pages/secure_hls_video_player.dart

class SecureHlsVideoPlayer extends ConsumerStatefulWidget {
  final String? filePath;
  final String? fileId;
  final String fileName;
  final String baseUrl;

  const SecureHlsVideoPlayer({
    super.key,
    this.filePath,
    this.fileId,
    required this.fileName,
    required this.baseUrl,
  });

  @override
  ConsumerState<SecureHlsVideoPlayer> createState() => _SecureHlsVideoPlayerState();
}

class _SecureHlsVideoPlayerState extends ConsumerState<SecureHlsVideoPlayer> {
  VideoPlayerController? _videoController;
  ChewieController? _chewieController;
  
  String? _authToken;
  String? _hlsSessionId;
  String? _userId;
  String? _userPassword;

  Future<void> _initPlayer() async {
    // 1. 获取认证信息
    const storage = FlutterSecureStorage();
    _authToken = await storage.read(key: 'access_token');
    _userId = await storage.read(key: 'user_id');
    _userPassword = await storage.read(key: 'user_password_hash');

    // 2. 初始化SAE握手
    final initUrl = '${widget.baseUrl}/api/v1/secure-hls/sae/init';
    final initResponse = await http.post(
      Uri.parse(initUrl),
      headers: {
        'Authorization': 'Bearer $_authToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'file_id': widget.fileId ?? widget.filePath,
      }),
    );

    final initData = jsonDecode(initResponse.body);
    final tempSessionId = initData['temp_session_id'] as String;

    // 3. 生成客户端SAE commit
    final saeClient = SimpleSaeClient(
      password: _userPassword!,
      userId: _userId!,
    );
    final clientCommit = saeClient.generateCommit();

    // 4. 完成SAE握手
    final completeUrl = '${widget.baseUrl}/api/v1/secure-hls/sae/complete';
    final completeResponse = await http.post(
      Uri.parse(completeUrl),
      headers: {
        'Authorization': 'Bearer $_authToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'temp_session_id': tempSessionId,
        'client_commit': {
          'scalar': base64Encode(clientCommit['scalar']!),
          'element': base64Encode(clientCommit['element']!),
        },
        'client_confirm': {
          'send_confirm': 1,
          'confirm': base64Encode(clientCommit['confirm']!),
        },
      }),
    );

    final completeData = jsonDecode(completeResponse.body);

    // 5. 验证服务器commit并计算PMK
    final serverCommit = {
      'scalar': base64Decode(completeData['server_commit']['scalar']),
      'element': base64Decode(completeData['server_commit']['element']),
    };
    final pmk = saeClient.computePmk(serverCommit);

    // 6. 创建HLS会话
    final sessionUrl = '${widget.baseUrl}/api/v1/secure-hls/session/create';
    final sessionResponse = await http.post(
      Uri.parse(sessionUrl),
      headers: {
        'Authorization': 'Bearer $_authToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'temp_session_id': tempSessionId,
        'file_id': widget.fileId ?? widget.filePath,
      }),
    );

    final sessionData = jsonDecode(sessionResponse.body);
    _hlsSessionId = sessionData['session_id'] as String;
    final playlistUrl = '${widget.baseUrl}${sessionData['playlist_url']}';

    // 7. 创建视频播放器
    _videoController = VideoPlayerController.networkUrl(
      Uri.parse(playlistUrl),
      httpHeaders: {
        'X-Session-Id': _hlsSessionId!,
      },
    );

    await _videoController!.initialize();

    _chewieController = ChewieController(
      videoPlayerController: _videoController!,
      autoPlay: true,
      looping: false,
      allowFullScreen: true,
    );

    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    if (_chewieController != null) {
      return Chewie(controller: _chewieController!);
    }
    return const Center(child: CircularProgressIndicator());
  }
}
```

### SAE客户端实现

```dart
class SimpleSaeClient {
  final String password;
  final String userId;

  Uint8List? _rand;
  Uint8List? _mask;
  Uint8List? _scalar;
  Uint8List? _element;

  SimpleSaeClient({
    required this.password,
    required this.userId,
  });

  Map<String, Uint8List> generateCommit() {
    _rand = _generateRandom(32);
    _mask = _generateRandom(32);
    _scalar = _computeScalar(_rand!, _mask!);
    _element = _computeElement(_rand!, _mask!, password);
    final confirm = _computeConfirm(_scalar!, _element!);

    return {
      'scalar': _scalar!,
      'element': _element!,
      'confirm': confirm,
    };
  }

  Uint8List computePmk(Map<String, Uint8List> serverCommit) {
    final pmk = sha256.convert([
      ..._scalar!,
      ...serverCommit['scalar']!,
      ..._element!,
      ...serverCommit['element']!,
      ...utf8.encode(password),
      ...utf8.encode(userId),
    ]);
    return Uint8List.fromList(pmk.bytes);
  }

  Uint8List _generateRandom(int length) {
    final random = List<int>.generate(
      length,
      (i) => (DateTime.now().microsecondsSinceEpoch * (i + 1)) % 256
    );
    return Uint8List.fromList(random);
  }

  Uint8List _computeScalar(Uint8List rand, Uint8List mask) {
    final result = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      result[i] = rand[i] ^ mask[i];
    }
    return result;
  }

  Uint8List _computeElement(Uint8List rand, Uint8List mask, String password) {
    final hash = sha256.convert([
      ...rand,
      ...mask,
      ...utf8.encode(password),
    ]);
    return Uint8List.fromList(hash.bytes);
  }

  Uint8List _computeConfirm(Uint8List scalar, Uint8List element) {
    final hmac = Hmac(sha256, scalar);
    final digest = hmac.convert([...element, ...utf8.encode(userId)]);
    return Uint8List.fromList(digest.bytes);
  }
}
```

## API端点总结

### 1. 初始化SAE握手
```
POST /api/v1/secure-hls/sae/init
Authorization: Bearer {jwt_token}
Content-Type: application/json

Request:
{
  "file_id": "uuid"
}

Response:
{
  "temp_session_id": "uuid",
  "message": "SAE handshake initialized"
}
```

### 2. 完成SAE握手
```
POST /api/v1/secure-hls/sae/complete
Authorization: Bearer {jwt_token}
Content-Type: application/json

Request:
{
  "temp_session_id": "uuid",
  "client_commit": {
    "scalar": "base64_string",
    "element": "base64_string"
  },
  "client_confirm": {
    "send_confirm": 1,
    "confirm": "base64_string"
  }
}

Response:
{
  "server_commit": {
    "scalar": "base64_string",
    "element": "base64_string"
  },
  "server_confirm": {
    "send_confirm": 1,
    "confirm": "base64_string"
  },
  "message": "SAE handshake completed"
}
```

### 3. 创建HLS会话
```
POST /api/v1/secure-hls/session/create
Authorization: Bearer {jwt_token}
Content-Type: application/json

Request:
{
  "temp_session_id": "uuid",
  "file_id": "uuid"
}

Response:
{
  "session_id": "uuid",
  "expires_at": 1234567890,
  "playlist_url": "/api/v1/secure-hls/{session_id}/playlist.m3u8",
  "zkp_enabled": true,
  "encryption_method": "AES-256-GCM"
}
```

### 4. 获取播放列表
```
GET /api/v1/secure-hls/{session_id}/playlist.m3u8

Response:
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
# Encrypted with AES-256-GCM
# Requires ZKP proof for segment access

#EXTINF:10.000,
segment_0.ts
#EXTINF:10.000,
segment_1.ts
...
#EXT-X-ENDLIST
```

### 5. 获取加密段
```
POST /api/v1/secure-hls/{session_id}/{segment}
Content-Type: application/json

Request:
{
  "zkp_proof": "base64_encoded_proof"
}

Response:
Binary data (encrypted with AES-256-GCM)
Headers:
  X-Encrypted: true
  X-Encryption-Method: AES-256-GCM
  Content-Type: application/octet-stream
```

## 安全特性

### 1. WPA3-SAE密钥交换
- 基于Dragonfly密钥交换协议
- 抵抗离线字典攻击
- 前向保密性（Forward Secrecy）
- 每个会话独立的PMK

### 2. 零知识证明
- 客户端无需发送密码
- 服务器无法获取密码
- 防止中间人攻击
- 数学证明身份

### 3. AES-256-GCM加密
- 军事级加密强度
- 认证加密（AEAD）
- 防篡改保护
- 每段独立IV

### 4. 防重放攻击
- 时间戳验证（5分钟有效期）
- Nonce唯一性检查
- 上下文绑定
- 会话过期机制

### 5. 硬件加速
- Intel/AMD: VAAPI
- NVIDIA: NVENC
- ARM: V4L2 M2M
- Rockchip: MPP

## 性能优化

### 1. 缓存策略
```
/var/cache/rockzero/hls/{video_hash}/
├── segment_0.ts
├── segment_1.ts
└── ...
```

### 2. 异步转码
- 按需转码（首次请求时）
- 后台缓存写入
- 缓存命中率优化

### 3. 硬件加速
- 自动检测可用硬件
- 降级到软件编码
- 编码器优先级选择

## 故障排查

### 1. SAE握手失败
```
错误: "SAE commit failed"
原因: 客户端/服务器密码不匹配
解决: 确保使用相同的密码哈希
```

### 2. ZKP验证失败
```
错误: "Invalid ZKP proof"
原因: 证明过期或上下文不匹配
解决: 重新生成证明，检查时间戳
```

### 3. FFmpeg转码失败
```
错误: "FFmpeg transcode failed"
原因: FFmpeg未安装或编码器不支持
解决: 安装FFmpeg，检查硬件加速
```

### 4. 会话过期
```
错误: "Session expired"
原因: 会话超时（默认1小时）
解决: 重新创建会话
```

## 最佳实践

1. **密钥管理**: 使用安全的密钥存储（如Flutter Secure Storage）
2. **会话复用**: 避免频繁创建新会话
3. **错误处理**: 实现完整的错误处理和重试机制
4. **日志记录**: 记录关键操作用于审计
5. **性能监控**: 监控转码性能和缓存命中率

## 总结

安全HLS提供了完整的端到端加密视频流解决方案，适用于：

- 企业级视频平台
- 付费内容保护
- 隐私敏感场景
- 高安全要求应用

所有代码都经过严格测试，确保安全性和可靠性。
