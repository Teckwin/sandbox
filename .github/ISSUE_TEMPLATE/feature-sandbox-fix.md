# [Feature] 修复沙箱功能缺失和不完整实现

## 问题描述

当前沙箱功能存在多个不完整实现和功能缺失，需要修复完善。

## 详细问题列表

### 1. 网络规则未实际执行 [高优先级]
- **位置**: `src/execpolicy/mod.rs`
- **问题**: `NetworkRule` 结构体存在，规则只存储但从未被实际执行
- **影响**: 文件系统沙箱有实际执行，网络规则形同虚设

### 2. Windows 防火墙集成未实现 [高优先级]
- **位置**: `src/windows_sandbox/mod.rs`
- **问题**: 文档中提到网络访问限制，但代码中没有实际调用 Windows Firewall API
- **影响**: `network_allowed` 布尔值存在但无实际效果

### 3. FreeBSD Capsicum 执行是存根 [高优先级]
- **位置**: `src/linux_sandbox/bsd.rs`
- **问题**: `execute_with_capsicum()` 只是 spawn 进程，没有调用 `cap_enter()` 进入 capability mode
- **影响**: FreeBSD 沙箱无法真正限制进程权限

### 4. OpenBSD pledge 执行未集成 [高优先级]
- **位置**: `src/linux_sandbox/bsd.rs`
- **问题**: `execute_with_pledge()` 存在但未与 SandboxManager 集成
- **影响**: OpenBSD 沙箱无法通过统一 API 使用

### 5. Policy 引擎缺少路径规则 [中优先级]
- **位置**: `src/execpolicy/mod.rs`
- **问题**: 只有前缀匹配，缺少基于文件路径的访问规则
- **影响**: 无法限制命令对特定文件路径的访问

### 6. Windows 沙箱级别映射错误 [中优先级]
- **位置**: `src/windows_sandbox/mod.rs` line 672
- **问题**: `policy_full` 映射到 `WindowsSandboxLevel::Strict` 但应该是 `Full`

### 7. macOS Localhost 实现过于宽松 [低优先级]
- **位置**: `src/sandboxing/mod.rs`
- **问题**: 使用 `(allow network* (local ip))` 过于宽松，应限制到特定 loopback 地址

## 修复计划

1. 实现 NetworkRule 实际执行逻辑
2. 添加 Windows Firewall API 集成
3. 完善 FreeBSD Capsicum 真正执行
4. 将 OpenBSD pledge 集成到 SandboxManager
5. 添加路径规则到 Policy 引擎
6. 修复 Windows 沙箱级别映射
7. 改进 macOS Localhost 策略

## 附加问题

- 代码中存在大量 `#[allow(dead_code)]` 属性，可能存在未使用代码或代码残缺
- 建议后续代码审查清理