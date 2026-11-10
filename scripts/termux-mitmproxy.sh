#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

pkg update -y
pkg install -y python openssl
python -m pip install --upgrade pip
python -m pip install mitmproxy

echo
echo "mitmproxy is ready."
echo "Start the proxy with:"
echo "  mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-host 127.0.0.1 --web-port 8081"
echo
echo "Open the local dashboard at http://127.0.0.1:8081"
echo "Configure only your own test device to use this phone's LAN IP on port 8080."
echo "Install the mitmproxy CA only on a test device you own or administer."
