#!/bin/bash
# Push to GitHub script for ai-sandbox

set -e

REPO_URL="https://github.com/Teckwin/sandbox.git"
BRANCH="main"

echo "=== GitHub Push Script ==="
echo "Repository: $REPO_URL"
echo "Branch: $BRANCH"
echo ""

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git add -A
    git commit -m "Initial commit: ai-sandbox v0.1.0"
fi

# Add remote if not exists
if ! git remote get-url origin 2>/dev/null; then
    echo "Adding remote: $REPO_URL"
    git remote add origin $REPO_URL
else
    echo "Remote already exists"
fi

# Push to GitHub
echo "Pushing to GitHub..."
git push -u origin $BRANCH

echo ""
echo "=== Done! ==="
echo "Repository URL: $REPO_URL"
echo ""
echo "GitHub Actions will automatically run tests."
echo "Check: $REPO_URL/actions"