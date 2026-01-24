# RockZero ZKP FFI Library

**Production-Grade Bulletproofs Zero-Knowledge Proof FFI for Flutter**

This library provides complete, non-simplified Bulletproofs implementation for secure video streaming authentication.

## Features

- ✅ **Complete Bulletproofs Range Proofs** (not simplified)
- ✅ **Schnorr Proofs** for password knowledge
- ✅ **PBKDF Key Stretching** (100,000 iterations)
- ✅ **Merlin Transcript** for Fiat-Shamir transform
- ✅ **Replay Attack Prevention** (timestamp + nonce)
- ✅ **Thread-Safe** operations
- ✅ **Memory-Safe** FFI interface

## Building

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install required targets
rustup target add x86_64-pc-windows-msvc  # Windows
rustup target add x86_64-unknown-linux-gnu  # Linux
rustup target add aarch64-linux-android  # Android ARM64
rustup target add armv7-linux-androideabi  # Android ARM32
rustup target add x86_64-apple-darwin  # macOS Intel
rustup target add aarch64-apple-darwin  # macOS Apple Silicon
```

### Build for Desktop

```bash
# Windows
cargo build --release --target x86_64-pc-windows-msvc

# Linux
cargo build --release --target x86_64-unknown-linux-gnu

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS Apple Silicon
cargo build --release --target aarch64-apple-darwin
```

### Build for Android

```bash
# Install Android NDK
# Set ANDROID_NDK_HOME environment variable

# ARM64 (most modern devices)
cargo build --release --target aarch64-linux-android

# ARM32 (older devices)
cargo build --release --target armv7-linux-androideabi

# x86_64 (emulators)
cargo build --release --target x86_64-linux-android
```

### Build for iOS

```bash
# Install iOS targets
rustup target add aarch64-apple-ios
rustup target add x86_64-apple-ios  # Simulator

# Build
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios
```

## Installation

### Windows

```bash
# Build
cargo build --release --target x86_64-pc-windows-msvc

# Copy to Flutter project
copy target\x86_64-pc-windows-msvc\release\rockzero_zkp_ffi.dll ..\RockZeroOS-UI\windows\
```

### Linux

```bash
# Build
cargo build --release --target x86_64-unknown-linux-gnu

# Copy to Flutter project
cp target/x86_64-unknown-linux-gnu/release/librockzero_zkp_ffi.so ../RockZeroOS-UI/linux/
```

### macOS

```bash
# Build for current architecture
cargo build --release

# Copy to Flutter project
cp target/release/librockzero_zkp_ffi.dylib ../RockZeroOS-UI/macos/
```

### Android

```bash
# Build for all Android architectures
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target x86_64-linux-android

# Create jniLibs directory structure
mkdir -p ../RockZeroOS-UI/android/app/src/main/jniLibs/arm64-v8a
mkdir -p ../RockZeroOS-UI/android/app/src/main/jniLibs/armeabi-v7a
mkdir -p ../RockZeroOS-UI/android/app/src/main/jniLibs/x86_64

# Copy libraries
cp target/aarch64-linux-android/release/librockzero_zkp_ffi.so \
   ../RockZeroOS-UI/android/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/librockzero_zkp_ffi.so \
   ../RockZeroOS-UI/android/app/src/main/jniLibs/armeabi-v7a/

cp target/x86_64-linux-android/release/librockzero_zkp_ffi.so \
   ../RockZeroOS-UI/android/app/src/main/jniLibs/x86_64/
```

### iOS

```bash
# Build universal library
cargo build --release --target aarch64-apple-ios
cargo build --release --target x86_64-apple-ios

# Create universal binary
lipo -create \
  target/aarch64-apple-ios/release/librockzero_zkp_ffi.a \
  target/x86_64-apple-ios/release/librockzero_zkp_ffi.a \
  -output ../RockZeroOS-UI/ios/librockzero_zkp_ffi.a
```

## Usage in Flutter

```dart
import 'package:rockzero/services/zkp/hls_bulletproof_auth.dart';

// Initialize
final auth = HlsBulletproofAuth();
if (!auth.initializeAuto()) {
  print('Failed to initialize ZKP FFI');
  return;
}

// Register password (during user registration)
final registration = auth.registerPassword('MySecureP@ssw0rd!');
// Store registration.toJsonString() on server

// Generate proof for HLS segment access
final proofBase64 = auth.generateProof(
  'MySecureP@ssw0rd!',
  registration,
  context: 'hls_segment_access',
);

// Send proofBase64 to server for verification
```

## API Reference

### C Functions

```c
// Register a password
FfiResult rz_zkp_register_password(const char* password);

// Generate enhanced proof
FfiResult rz_zkp_generate_enhanced_proof(
    const char* password,
    const char* registration_json,
    const char* context
);

// Verify enhanced proof
FfiResult rz_zkp_verify_enhanced_proof(
    const char* proof_base64,
    const char* registration_json,
    const char* expected_context,
    int64_t max_age_seconds
);

// Calculate password entropy
int64_t rz_zkp_calculate_entropy(const char* password);

// Get minimum entropy requirement
int64_t rz_zkp_min_entropy_bits();

// Free string
void rz_zkp_free_string(char* ptr);

// Clear nonces (testing only)
void rz_zkp_clear_nonces();

// Get version
const char* rz_zkp_version();
```

## Security Considerations

### Password Requirements

- Minimum entropy: 28 bits
- Recommended: Use strong passwords with mixed character types
- Example: `MySecureP@ssw0rd123!` (≥ 28 bits entropy)

### Proof Validity

- Default max age: 300 seconds (5 minutes)
- Nonces are tracked to prevent replay attacks
- Context binding prevents cross-context attacks

### Thread Safety

- All functions are thread-safe
- Global state is protected by mutexes
- Safe to call from multiple threads

## Testing

```bash
# Run tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_enhanced_proof_generation_and_verification
```

## Troubleshooting

### Library Not Found

**Windows:**
```
Error: DynamicLibrary.open failed: rockzero_zkp_ffi.dll not found
```
Solution: Copy `rockzero_zkp_ffi.dll` to `RockZeroOS-UI/windows/` or add to PATH

**Linux:**
```
Error: DynamicLibrary.open failed: librockzero_zkp_ffi.so not found
```
Solution: Copy `librockzero_zkp_ffi.so` to `RockZeroOS-UI/linux/` or `/usr/local/lib/`

**macOS:**
```
Error: DynamicLibrary.open failed: librockzero_zkp_ffi.dylib not found
```
Solution: Copy `librockzero_zkp_ffi.dylib` to `RockZeroOS-UI/macos/`

### Android Build Issues

If you encounter NDK errors:
```bash
# Set NDK path
export ANDROID_NDK_HOME=/path/to/android-ndk

# Install cargo-ndk
cargo install cargo-ndk

# Build with cargo-ndk
cargo ndk -t arm64-v8a -o ../RockZeroOS-UI/android/app/src/main/jniLibs build --release
```

### iOS Build Issues

If you encounter linking errors:
```bash
# Ensure Xcode is installed
xcode-select --install

# Add library to Xcode project
# 1. Open RockZeroOS-UI/ios/Runner.xcworkspace
# 2. Add librockzero_zkp_ffi.a to "Link Binary With Libraries"
# 3. Add library search path: $(PROJECT_DIR)
```

## Performance

- **Registration**: ~100ms (PBKDF2 100k iterations)
- **Proof Generation**: ~50ms (Schnorr + Bulletproofs)
- **Proof Verification**: ~30ms (Schnorr + Bulletproofs)

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-repo/issues
- Documentation: https://docs.your-domain.com
