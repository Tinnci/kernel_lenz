# Kallsyms Scanner 对比分析报告

**对比项目**:
- **vmlinux-to-elf** (Python): [marin-m/vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)
- **kernel_lenz** (Rust): 本项目 `crates/kernel_core/src/kallsyms/scanner.rs`

**日期**: 2026-01-03

---

## 📊 功能对比矩阵

| 功能 | vmlinux-to-elf | kernel_lenz | 差距 |
|------|----------------|-------------|------|
| **Token Table 发现** | ✅ 搜索 "0123456789" + 避免特定模式 | ⚠️ 搜索 "0\\01\\0...9\\0" | 缺少避免模式 |
| **Token Index 验证** | ✅ 自动推导偏移 | ✅ 构建 LE/BE 模式匹配 | 相当 |
| **Markers 验证** | ✅ 递增检查 + 范围 0x200-0x4000 | ⚠️ 范围 0x40-0x10000 (过于宽松) | 需收紧 |
| **符号数量验证** | ✅ 最小 256 符号 + DP 算法 | ⚠️ 仅范围检查 | 缺少 DP 验证 |
| **地址零值检查** | ✅ 超过 20% 则重试 | ❌ 未实现 | **重要缺失** |
| **负偏移启发式** | ✅ 位掩码检测 + 警告 | ❌ 未实现 | **重要缺失** |
| **OpenWRT 未压缩格式** | ✅ 回退支持 | ❌ 未实现 | 可选改进 |
| **多参数启发式** | ✅ 循环尝试 (relative/absolute, 不同整数大小) | ⚠️ 仅尝试不同架构 | 需增强 |
| **符号类型验证** | ✅ 验证类型字符有效性 | ⚠️ 仅在 ELF 构建时过滤 | 应提前验证 |
| **基址合理性检查** | ✅ 启发式警告 | ❌ 未实现 | **导致当前问题** |

---

## 🔍 详细分析

### 1. Token Table 发现

**vmlinux-to-elf**:
```python
sequence_to_find = b''.join(b'%c\0' % i for i in range(ord('0'), ord('9') + 1))
sequences_to_avoid = [b':\0', b'\0\0', b'\0\1', b'\0\2', b'ASCII\0']

# 避免特定模式，减少误报
for seq in sequences_to_avoid:
    if self.kernel_img[pos:pos + len(seq)] == seq:
        break
```

**kernel_lenz**:
```rust
// 只搜索模式，没有避免逻辑
let mut seq = Vec::with_capacity(20);
for i in b'0'..=b'9' { seq.push(i); seq.push(0); }
```

**改进建议**: 添加 `sequences_to_avoid` 检查。

---

### 2. Markers 验证

**vmlinux-to-elf** (更严格):
```python
# 增量范围: 0x200 - 0x4000
if entries[i-1]+0x200 > entries[i] or entries[i-1]+0x4000 < entries[i]:
    break
```

**kernel_lenz** (过于宽松):
```rust
// 增量范围: 0x40 - 0x10000 (太宽了!)
if val <= last_val || val < last_val + 0x40 || val > last_val + 0x10000 {
    valid = false;
}
```

**改进建议**: 收紧到 `0x100 - 0x8000` 范围。

---

### 3. 地址表验证 (关键缺失!)

**vmlinux-to-elf**:
```python
# 1. 零地址比例检查
number_of_null_items = len([addr for addr in addresses if addr == 0])
if number_of_null_items / len(addresses) >= 0.2:
    if can_skip: continue  # 尝试其他参数

# 2. 负偏移启发式 (相对寻址内核)
NEGATIVE_HEURISTIC_MASK = 0xFFF << (BITS - 12)
heuristically_negative = len([off for off in offsets if (off & MASK) == MASK])
if heuristic_negative_percent < 0.5:
    logging.warning('Less than half of offsets are negative')
```

**kernel_lenz**:
```rust
// ❌ 没有这些验证!
// 直接信任找到的 base 地址，导致 0xffffffffff091f1f 被接受
```

**这就是当前问题的根本原因**: 扫描器找到了错误的 `relative_base`，没有验证其合理性。

---

### 4. 多参数启发式搜索

**vmlinux-to-elf**:
```python
for (has_base_relative, can_skip) in heuristic_search_parameters:
    for address_byte_size in [8, 4]:
        # 尝试解析
        # 如果失败且 can_skip，继续下一组参数
```

**kernel_lenz**:
```rust
// 只尝试不同架构，没有 can_skip 机制
for arch in archs_to_try {
    // Strategy 1: Absolute
    // Strategy 2: Relative
    // 找到第一个就返回，不验证质量
}
```

**改进建议**: 添加候选评分系统，选择最佳结果。

---

## 🛠️ 需要实现的改进

### 优先级 P0 (导致当前崩溃)

1. **地址表质量验证**
   ```rust
   fn validate_addresses(addresses: &[u64]) -> AddressQuality {
       let null_ratio = addresses.iter().filter(|&&a| a == 0).count() as f32 
                        / addresses.len() as f32;
       if null_ratio >= 0.2 {
           return AddressQuality::TooManyNulls;
       }
       // ... 更多检查
   }
   ```

2. **负偏移启发式检查**
   ```rust
   fn check_relative_offsets(offsets: &[i32], bits: u32) -> bool {
       let negative_mask = 0xFFF << (bits - 12);
       let negative_count = offsets.iter()
           .filter(|&&o| (o as u64 & negative_mask) == negative_mask)
           .count();
       negative_count as f32 / offsets.len() as f32 >= 0.5
   }
   ```

3. **基址合理性检查**
   ```rust
   fn is_valid_kernel_base(base: u64, arch: KernelArch) -> bool {
       match arch {
           KernelArch::Arm64 => {
               // 典型 AArch64 内核基址模式
               (base & 0xFFFF_0000_0000_0000) == 0xFFFF_8000_0000_0000 ||
               (base & 0xFFFF_0000_0000_0000) == 0xFFFF_FC00_0000_0000
           }
           // ...
       }
   }
   ```

### 优先级 P1 (提高鲁棒性)

4. **收紧 Markers 增量范围** (`0x200 - 0x4000`)

5. **Token Table 避免模式**

6. **候选评分系统**: 找到多个候选后，计算质量分数，选择最佳

### 优先级 P2 (可选)

7. **OpenWRT 未压缩格式支持**

8. **动态规划符号表验证**

---

## 📈 当前问题诊断

日志显示:
```
Found relative addresses table at 0x1372c30 with base 0xffffffffff091f1f
```

**问题**: `0xffffffffff091f1f` 不是有效的内核基址！

典型的 AArch64 内核基址:
- `0xffffffc000000000` (KASLR disabled)
- `0xffff800000000000` (VA_BITS=48)
- `0xffff000000000000` (VA_BITS=52)

`0xffffffffff091f1f` 的问题:
- 低 24 位 (`0x091f1f`) 不是页对齐的 (应该是 `0x000000`)
- 看起来像随机数据被误识别为基址

---

## 📝 总结

| 方面 | vmlinux-to-elf | kernel_lenz | 评估 |
|------|----------------|-------------|------|
| **代码成熟度** | 高 (经过广泛测试) | 中 | - |
| **验证层级** | 多层验证 + 回退 | 单层验证 | 需改进 |
| **错误恢复** | 优雅降级 | 快速失败 | 可接受 |
| **日志信息** | 详细警告 | 基础日志 | 可改进 |

**结论**: 我们的实现缺少关键的验证步骤，特别是 **地址表质量验证** 和 **基址合理性检查**，这直接导致了当前的符号解码乱码问题。
