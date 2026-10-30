#!/bin/bash
# Rebuild static/css/tailwind.css with the Tailwind v3 standalone CLI.
# Works on Linux, macOS and Windows (Git Bash). Keep VERSION in step with the
# Dockerfile, which builds the production stylesheet the same way.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="v3.4.17"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)               ASSET="tailwindcss-linux-x64" ;;
    Linux-aarch64|Linux-arm64)  ASSET="tailwindcss-linux-arm64" ;;
    Darwin-x86_64)              ASSET="tailwindcss-macos-x64" ;;
    Darwin-arm64)               ASSET="tailwindcss-macos-arm64" ;;
    MINGW*|MSYS*|CYGWIN*)       ASSET="tailwindcss-windows-x64.exe" ;;
    *) echo "Unsupported platform: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

BIN=".tailwind/$VERSION/$ASSET"
if [ ! -f "$BIN" ]; then
    echo "Downloading Tailwind CSS $VERSION CLI ($ASSET)..."
    mkdir -p "$(dirname "$BIN")"
    curl -fsSL "https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/$ASSET" -o "$BIN"
    chmod +x "$BIN"
fi

echo "Building Tailwind CSS..."
"$BIN" -i static/css/input.css -o static/css/tailwind.css -c tailwind.config.js --minify

echo "✅ CSS rebuilt successfully!"
