---
name: ai-sandbox-release
description: |
  AI Sandbox 项目专门的发布工作流。本地skill针对当前项目结构进行优化，确保：
  1. 只有通过本地验证（ai-sandbox-dev workflow）+ CI验证的代码才能发布
  2. 版本号在功能分支上更新，PR合并后main直接就是新版本
  3. 发布流程必须由用户主动要求才执行
  4. 完整的发布流程包括：PR合并 → 同步main → TAG标记 → GitHub Release → 可选crates.io发布

  本地验证请先使用 ai-sandbox-dev skill 进行完整的本地检查。
---

# AI Sandbox 发布工作流

本skill是 ai-sandbox-dev 的后续流程，用于在代码通过验证后的发布阶段。

## 核心流程

```
功能分支开发 → 版本号更新 → 本地验证 → CI验证 → PR合并到main → 用户确认 → 同步main → 创建TAG → GitHub Release → (可选) crates.io
```

## 前提条件（必须满足）

在执行发布流程前，必须确认：

- [ ] 已使用 `ai-sandbox-dev` skill 完成本地验证并通过
- [ ] 代码已推送到远程分支
- [ ] CI 验证全部通过（检查 GitHub Actions）
- [ ] 版本号已在功能分支更新（Cargo.toml）
- [ ] CHANGELOG 已更新
- [ ] PR 已合并到 main 分支
- [ ] 用户已明确确认要发布

## 发布前检查

### 1. 检查 CI 状态

```bash
# 查看最近的 CI 运行状态
gh run list --limit 10 --repo Teckwin/sandbox

# 确认所有 jobs 都通过
gh run list --branch main --status success
```

### 2. 检查版本号是否已更新

**重要**：版本号必须在功能分支上更新，而不是在合并到main后再更新。

```bash
# 查看当前版本（应该在main上）
git checkout main
git pull origin main
grep 'version = ' /Users/ryota/works/sandbox/Cargo.toml

# 查看上一个版本标签
git tag --sort=-v:refname | head -1
```

### 3. 确认版本号和CHANGELOG在PR中

版本号更新和CHANGELOG更新应该在功能分支的PR中一起合并到main，而不是在发布时才更新。

```bash
# 确认main上包含版本更新
git log --oneline main | head -5

# 查看CHANGELOG是否包含新版本
head -30 /Users/ryota/works/sandbox/CHANGELOG.md
```

### 4. 获取用户确认

**重要**：在继续发布前，必须获得用户明确确认。

向用户展示以下信息并确认：

```
=== 发布确认 ===

当前版本: x.y.z (main分支)
CI 状态: ✅ 通过
PR 状态: ✅ 已合并

发布内容:
- 新功能: ...
- 修复: ...
- 破坏性变更: ...

发布目标:
- [ ] GitHub TAG (必须)
- [ ] GitHub Release (必须)
- [ ] crates.io (可选)

确认发布? (是/否)
```

---

## 发布执行

### 步骤1: 同步 main 分支

```bash
cd /Users/ryota/works/sandbox

# 确保本地 main 分支是最新的
git checkout main
git pull origin main

# 确认要发布的 commit 在 main 上
git log --oneline -3
```

### 步骤2: 创建版本标签

```bash
# 创建版本标签（main上已经是新版本，直接打tag）
git tag -a v1.0.0 -m "Release v1.0.0

## 新增功能
- 功能A

## 修复问题
- 问题X修复

## 破坏性变更
- 无"

# 推送标签
git push origin v1.0.0
```

### 步骤3: 创建 GitHub Release

```bash
# 方法1: 使用 CHANGELOG 文件
gh release create v1.0.0 \
  --title "Release v1.0.0" \
  --notes-file /Users/ryota/works/sandbox/CHANGELOG.md \
  --target main \
  --latest

# 方法2: 手动编写 Release Notes
gh release create v1.0.0 \
  --title "Release v1.0.0" \
  --notes "## What's Changed

### 新增功能
- 功能A实现 (@contributor)

### 修复
- 问题X修复 (@contributor)

### 其他
- 依赖更新

**Full Changelog**: https://github.com/Teckwin/sandbox/compare/v0.x.0...v1.0.0" \
  --target main \
  --latest
```

### 步骤4: (可选) 发布到 crates.io

```bash
cd /Users/ryota/works/sandbox

# 先进行 dry-run 测试
cargo publish --dry-run --manifest-path /Users/ryota/works/sandbox/Cargo.toml

# 确认无误后正式发布
cargo publish --manifest-path /Users/ryota/works/sandbox/Cargo.toml
```

---

## 发布后验证

发布完成后，确认以下内容：

- [ ] 标签已推送到 GitHub
- [ ] GitHub Release 已创建
- [ ] (可选) crates.io 包已更新

```bash
# 确认标签
git ls-remote --tags origin

# 确认 Release
gh release list --repo Teckwin/sandbox
```

---

## 回滚流程

如果发布出现问题，需要回滚：

```bash
# 1. 删除远程标签
git push origin --delete v1.0.0

# 2. 删除本地标签
git tag -d v1.0.0

# 3. 如需修复后重新发布，创建新版本
git tag -a v1.0.1 -m "Hotfix release"
git push origin v1.0.1
```

---

## 版本号更新时机（重要）

**为什么版本号要在功能分支更新，而不是合并到main后再更新？**

这样可以确保：
1. tag 对应的 commit 直接就是版本号对应的代码
2. main 分支不会有额外的"版本更新"commit
3. 代码历史更清晰

**正确流程**：
```
feature/xxx 分支:
  - 实现功能
  - 更新 Cargo.toml 版本号 (0.1.0 → 0.2.0)
  - 更新 CHANGELOG
  - 提交 PR → CI 通过 → 合并到 main

发布时:
  - main 已经是 v0.2.0
  - 直接 git tag -a v0.2.0
  - 创建 GitHub Release
```

---

## 常见问题

### Q: 版本号可以在合并到main后再更新吗？
**不推荐**。这会导致main上多一个版本更新的commit，tag和代码不对应。正确的做法是在功能分支上就更新版本号。

### Q: CI 失败可以发布吗？
**不可以**。必须等待 CI 全部通过后才能发布。

### Q: PR 还没合并可以发布吗？
**不可以**。必须等 PR 合并到 main 后才能发布。

### Q: 可以跳过本地验证直接发布吗？
**不可以**。必须先使用 `ai-sandbox-dev` skill 完成本地验证。

### Q: 如何发布预发布版本？
```bash
# 创建预发布标签
git tag -a v1.0.0-beta.1 -m "Beta release v1.0.0-beta.1"

# 推送
git push origin v1.0.0-beta.1

# 创建预发布 Release
gh release create v1.0.0-beta.1 \
  --title "Release v1.0.0-beta.1" \
  --notes "Beta release for testing" \
  --prerelease
```

---

## 相关文件位置

- 项目根目录: `/Users/ryota/works/sandbox`
- CI 配置: `/Users/ryota/works/sandbox/.github/workflows/ci.yml`
- Cargo 配置: `/Users/ryota/works/sandbox/Cargo.toml`
- 本地验证: 使用 `ai-sandbox-dev` skill
- 全局发布流程: 使用 `release-workflow` skill