# mitmproxy on Android / Termux

This is the local-only integration for tool 27. It is intentionally not exposed as a public cloud proxy.

## Install

Open Termux on the Android phone and run:

    bash scripts/termux-mitmproxy.sh

Or install manually:

    pkg update
    pkg install python openssl
    python -m pip install mitmproxy

## Start

    mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-host 127.0.0.1 --web-port 8081

Open the dashboard on the same phone at `http://127.0.0.1:8081`. Configure only a test device you own or administer to use the phone's LAN IP and port 8080 as its HTTP proxy.

For HTTPS inspection, install the mitmproxy CA only on your own test device using the local `http://mitm.it` page. Modern Android applications may reject user-installed CA certificates; do not weaken a third-party device's security settings to bypass that restriction.

Stop the proxy with Ctrl+C. Do not expose port 8080 or the dashboard to the public internet.
