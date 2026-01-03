# Flutter 与 Rust 集成分析报告

**项目**: KernelLens - Linux Kernel Analysis Suite  
**日期**: 2026-01-03  
**分析者**: Antigravity AI Assistant

---

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Flutter App (Dart)                                │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  app/lib/                                                             │  │
│  │    ├── main.dart                    ← 入口点，调用 RustLib.init()      │  │
│  │    ├── src/rust/                                                      │  │
│  │    │    ├── api.dart                ← 自动生成的 Dart API 接口         │  │
│  │    │    ├── frb_generated.dart      ← FRB 核心生成代码（SSE编解码等）  │  │
│  │    │    ├── frb_generated.io.dart   ← 原生平台实现                     │  │
│  │    │    └── frb_generated.web.dart  ← Web 平台实现                     │  │
│  │    └── features/                                                      │  │
│  │         └── analysis/presentation/analysis_controller.dart            │  │
│  │              ↑ 业务逻辑，调用 startAnalysis() 等 Rust API              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                        │ FFI                                │
│                                        ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  rust_builder/                      ← Flutter Plugin (构建胶水层)      │  │
│  │    ├── cargokit/                    ← CargoKit (Rust 构建工具)         │  │
│  │    │    └── cmake/cargokit.cmake   ← CMake 集成脚本                   │  │
│  │    ├── windows/CMakeLists.txt       ← Windows 平台构建配置             │  │
│  │    └── pubspec.yaml                 ← ffiPlugin: true 配置            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼ Compiles & Links
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Rust Workspace                                     │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  crates/kernel_ffi/                 ← FFI 桥接层 (cdylib/staticlib)    │  │
│  │    ├── Cargo.toml                   ← flutter_rust_bridge 依赖         │  │
│  │    └── src/                                                           │  │
│  │         ├── api.rs                  ← 暴露给 Flutter 的公共 API       │  │
│  │         ├── frb_generated.rs        ← FRB 自动生成的 Rust 端胶水代码  │  │
│  │         └── lib.rs                  ← 模块入口                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                        │ depends on                         │
│                                        ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  crates/kernel_core/                ← 核心业务逻辑 (纯 Rust)           │  │
│  │    └── src/                                                           │  │
│  │         ├── boot_image.rs           ← Android Boot Image 解析         │  │
│  │         ├── compression.rs          ← LZ4/Gzip/Zstd 解压缩            │  │
│  │         ├── kallsyms/               ← Linux 内核符号表恢复            │  │
│  │         └── elf_builder.rs          ← ELF 文件重建                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 核心集成技术：`flutter_rust_bridge` (FRB)

该项目使用 **[flutter_rust_bridge](https://cjycode.com/flutter_rust_bridge/)** v2.11.1 作为 Flutter 和 Rust 之间的桥接方案。

### 2.1 配置文件

**`app/flutter_rust_bridge.yaml`**:
```yaml
rust_input: "crate::api"          # Rust 端需要暴露的 API 模块
rust_root: "../crates/kernel_ffi" # Rust crate 的根目录
dart_output: "lib/src/rust"       # Dart 生成代码的输出目录
dart_root: "."                    # Flutter 项目根目录
```

### 2.2 代码生成流程

```
flutter_rust_bridge_codegen generate
        │
        ├── 读取 crates/kernel_ffi/src/api.rs 中的公共类型和函数
        │
        ├── 生成 Rust 端：
        │   └── crates/kernel_ffi/src/frb_generated.rs
        │       (序列化/反序列化、Handler 包装、Arc 引用计数管理)
        │
        └── 生成 Dart 端：
            ├── app/lib/src/rust/api.dart          (用户友好的 API 接口)
            ├── app/lib/src/rust/frb_generated.dart (核心运行时)
            ├── app/lib/src/rust/frb_generated.io.dart (FFI 加载器)
            └── app/lib/src/rust/frb_generated.web.dart (WASM 加载器)
```

---

## 3. Rust API 层设计 (`api.rs`)

### 3.1 数据结构设计

```rust
/// Flutter-friendly 的符号结构体 (避免复杂 Rust 类型)
#[derive(Debug, Clone)]
pub struct FrbKernelSymbol {
    pub addr: u64,
    pub name: String,
    pub stype: String,
}

/// 进度更新 (用于流式传输)
pub struct ProgressUpdate {
    pub step: String,
    pub progress: f32,
    pub summary: Option<AnalysisSummary>,
    pub session: Option<AnalysisSession>,
}
```

### 3.2 流式 API (StreamSink)

```rust
/// 使用 StreamSink 实现实时进度推送
pub fn start_analysis(
    input_path: String,
    sink: crate::frb_generated::StreamSink<ProgressUpdate>,
) -> Result<()> {
    sink.add(ProgressUpdate {
        step: "Reading file...".to_string(),
        progress: 0.05,
        summary: None,
        session: None,
    })?;
    // ... 业务逻辑
}
```

在 Dart 端，这变成一个 `Stream<ProgressUpdate>`：

```dart
Stream<ProgressUpdate> startAnalysis({required String inputPath}) =>
    RustLib.instance.api.crateApiStartAnalysis(inputPath: inputPath);
```

### 3.3 Opaque 类型 (状态保持)

```rust
/// 使用 #[frb(opaque)] 保持 Rust 状态在 Rust 内存中
/// 避免将大对象 (10MB+ 符号表) 传输到 Dart
#[flutter_rust_bridge::frb(opaque)]
pub struct AnalysisSession {
    symbols: Vec<FrbKernelSymbol>,
    pub summary: AnalysisSummary,
    pub elf_bytes: Vec<u8>,
}

impl AnalysisSession {
    /// 服务端分页/过滤，只返回 UI 需要显示的子集
    pub fn query_symbols(&self, filter: String, ...) -> Vec<FrbKernelSymbol> {
        // 只克隆当前页的数据，非常高效
    }
}
```

这在 Dart 端表现为一个抽象类：

```dart
// Rust opaque 类型在 Dart 中是接口
abstract class AnalysisSession implements RustOpaqueInterface {
    Future<List<FrbKernelSymbol>> querySymbols({...});
    Future<HexChunk> getHexChunk({...});
    // ...
}
```

---

## 4. 构建集成：CargoKit + CMake

### 4.1 Flutter Plugin 结构

项目使用 **CargoKit** (FRB 推荐的构建工具) 将 Rust 库集成到 Flutter 构建系统：

**`rust_builder/pubspec.yaml`**:
```yaml
flutter:
  plugin:
    platforms:
      windows:
        ffiPlugin: true  # 告诉 Flutter 这是一个 FFI 插件
```

**`rust_builder/windows/CMakeLists.txt`**:
```cmake
include("../cargokit/cmake/cargokit.cmake")

# 计算 kernel_ffi crate 的绝对路径
get_filename_component(PROJECT_ROOT "${CMAKE_SOURCE_DIR}/../.." ABSOLUTE)
set(KERNEL_FFI_ABS_PATH "${PROJECT_ROOT}/crates/kernel_ffi")

# 调用 CargoKit 构建 Rust 库
apply_cargokit(${PROJECT_NAME} "${KERNEL_FFI_ABS_PATH}" kernel_ffi "")
```

### 4.2 构建流程

```
flutter run -d windows
        │
        ├── CMake 配置阶段
        │   └── include cargokit.cmake
        │       └── 设置环境变量 (CARGOKIT_MANIFEST_DIR 等)
        │
        ├── 构建阶段
        │   └── run_build_tool.cmd build-cmake
        │       └── cargo build --release -p kernel_ffi
        │           └── 输出 kernel_ffi.dll
        │
        └── 链接阶段
            └── Flutter runner 链接 kernel_ffi.dll
                └── 最终 .exe 包含 Rust 动态库
```

---

## 5. 运行时数据流

以分析一个 boot.img 为例：

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Flutter UI                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ AnalysisController.analyze(path)                                   │ │
│  │   ↓                                                                │ │
│  │ startAnalysis(inputPath: path)  ← Dart 调用                        │ │
│  │   ↓                             返回 Stream<ProgressUpdate>        │ │
│  │ stream.listen(onData, onError, onDone)                             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                      │                                  │
│                          FFI 边界    │  SSE 序列化                      │
│                                      ▼                                  │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ frb_generated.rs::start_analysis()                                 │ │
│  │   ↓                                                                │ │
│  │ api.rs::start_analysis(path, sink)                                 │ │
│  │   │                                                                │ │
│  │   ├─→ sink.add(ProgressUpdate { step: "Reading..." })              │ │
│  │   │        ↓ (推送到 Dart Stream)                                  │ │
│  │   │                                                                │ │
│  │   ├─→ kernel_core::BootImage::from_bytes()                         │ │
│  │   ├─→ kernel_core::Decompressor::decompress()                      │ │
│  │   ├─→ kernel_core::KallsymsFinder::new()                           │ │
│  │   ├─→ kernel_core::ElfBuilder::build()                             │ │
│  │   │                                                                │ │
│  │   └─→ sink.add(ProgressUpdate { session: Some(session) })          │ │
│  │        ↓ (最终结果推送到 Dart)                                     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                      │                                  │
│                          FFI 边界    │                                  │
│                                      ▼                                  │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ AnalysisController.state.session  ← AnalysisSession (Opaque)      │ │
│  │   ↓                                                                │ │
│  │ session.querySymbols(filter, page, pageSize)                       │ │
│  │   ↓                             服务端分页                          │ │
│  │ 只返回当前页 100 条记录                                             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. 设计亮点与最佳实践

### 6.1 分层架构

| 层级 | Crate | 职责 |
|------|-------|------|
| **核心逻辑** | `kernel_core` | 纯 Rust，无 FFI 依赖，可独立测试 |
| **FFI 桥接** | `kernel_ffi` | 仅负责类型转换和暴露 API |
| **构建胶水** | `rust_builder` | Flutter Plugin，处理跨平台构建 |

### 6.2 性能优化

1. **Opaque 类型**: `AnalysisSession` 保持在 Rust 内存中，避免复制 10MB+ 符号表
2. **服务端分页**: `query_symbols()` 只返回当前页数据
3. **流式进度**: 使用 `StreamSink` 而非轮询，实现实时 UI 更新
4. **懒加载十六进制**: `get_hex_chunk()` 按需加载，配合虚拟滚动

### 6.3 错误处理

Rust 端定义了语义化错误枚举：
```rust
#[derive(Debug, Clone, thiserror::Error)]
pub enum AnalysisError {
    #[error("File not found at path: {0}")]
    FileNotFound(String),
    #[error("Kallsyms not found: Kernel might be stripped or KASLR-active")]
    KallsymsNotFound,
    // ...
}
```

Dart 端映射到用户友好的 `FailureContext`：
```dart
FailureContext _mapError(String error) {
    if (error.contains('Kallsyms not found')) {
        return FailureContext(
            code: 'KALLSYMS_NOT_FOUND',
            message: 'Kernel Symbol Table Not Found',
            suggestion: '...',
        );
    }
    // ...
}
```

---

## 7. 总结

| 方面 | 技术选型 |
|------|----------|
| **桥接框架** | `flutter_rust_bridge` v2.11.1 |
| **构建工具** | CargoKit (CMake 集成) |
| **序列化协议** | SSE (Simple Serialization Engine) |
| **异步模式** | `StreamSink` (Rust → Dart 流) |
| **状态管理** | Opaque 类型 + 服务端分页 |
| **平台支持** | Windows, Linux, macOS, Android, iOS, Web |

这套架构实现了 **Flutter UI 的高效渲染** 与 **Rust 核心的高性能计算** 的完美结合，同时保持了良好的代码组织和可维护性。

---

## 附录：关键文件路径

| 文件 | 作用 |
|------|------|
| `app/flutter_rust_bridge.yaml` | FRB 代码生成配置 |
| `app/lib/src/rust/api.dart` | Dart 端 API 接口（自动生成）|
| `crates/kernel_ffi/src/api.rs` | Rust 端 API 定义 |
| `crates/kernel_ffi/Cargo.toml` | FFI crate 配置 (`cdylib`) |
| `app/rust_builder/pubspec.yaml` | Flutter FFI Plugin 配置 |
| `app/rust_builder/windows/CMakeLists.txt` | Windows 构建脚本 |
