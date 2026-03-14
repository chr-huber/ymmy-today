#!/bin/bash
# Script to rebuild Tailwind CSS with dark mode support

# Check if Tailwind CSS CLI is available
if [ ! -f "/tmp/tailwindcss-v3" ]; then
    echo "Downloading Tailwind CSS v3 CLI..."
    curl -sL https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.1/tailwindcss-linux-x64 -o /tmp/tailwindcss-v3
    chmod +x /tmp/tailwindcss-v3
fi

echo "Building Tailwind CSS with dark mode support..."
/tmp/tailwindcss-v3 -i static/css/input.css -o static/css/tailwind.css -c tailwind.config.js --minify

echo "✅ CSS rebuilt successfully!"
