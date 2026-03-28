#!/bin/bash
# 推送测试 tag 到 GitHub

set -e

REPO_URL="https://github.com/Teckwin/sandbox.git"
TAG_NAME="v0.1.0-test"

echo "=== GitHub Tag Push Script ==="
echo "Repository: $REPO_URL"
echo "Tag: $TAG_NAME"
echo ""

# 检查是否是 git 仓库
if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run 'git init' first."
    exit 1
fi

# 检查是否有提交
if ! git rev-parse HEAD >/dev/null 2>&1; then
    echo "Error: No commits yet. Make at least one commit."
    exit 1
fi

# 添加远程仓库
if ! git remote get-url origin 2>/dev/null; then
    echo "Adding remote..."
    git remote add origin $REPO_URL
fi

# 创建 tag
echo "Creating tag: $TAG_NAME"
git tag -a "$TAG_NAME" -m "Test release for CI validation"

# 推送到 GitHub
echo "Pushing to GitHub..."
git push origin main --tags

echo ""
echo "=== Done! ==="
echo "Tag pushed: $TAG_NAME"
echo "Check CI: $REPO_URL/actions"
echo ""
echo "或者手动触发 workflow:"