#!/bin/bash
# Test script for ai-sandbox

set -e

echo "========================================="
echo "AI Sandbox Test Script"
echo "========================================="

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust."
    exit 1
fi

cd "$(dirname "$0")"

echo ""
echo "1. Checking compilation..."
cargo check

echo ""
echo "2. Running tests..."
cargo test

echo ""
echo "3. Running demo example..."
cargo run --example demo

echo ""
echo "4. Building release version..."
cargo build --release

echo ""
echo "========================================="
echo "All tests passed!"
echo "========================================="