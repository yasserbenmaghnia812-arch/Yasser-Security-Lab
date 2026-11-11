# Local AI and Replicate MCP on Android

This setup keeps the Replicate API token and the GGUF model on the phone. The Android APK contains neither credential.

## 1. Local coding model

The supported starter model is **Qwen2.5-Coder-0.5B-Instruct GGUF, Q4_0** (about 429 MB). It is deliberately small for a 4 GB RAM Android device. It is a lightweight coding assistant, not a high-capability replacement for a cloud coding model.

In Termux, clone the repository and run:

    bash scripts/setup-local-ai-termux.sh

This installs build dependencies, builds `llama-server` with two compile jobs, and downloads the GGUF model into `$HOME/models`. Building llama.cpp on the phone can take time, use battery, and require additional temporary storage. Keep the model under Termux's private home directory rather than shared storage.

Start the local OpenAI-compatible server using the command printed by the script. The server binds only to `127.0.0.1:11434`. In the Android app's Local AI panel use:

- Base URL: `http://127.0.0.1:11434/v1`
- Model ID: `yasser-coder-0.5b`
- API key: empty

Use a context size of 1024 initially. Close other apps and stop inference when finished to reduce memory pressure.

## 2. Replicate MCP bridge

Replicate MCP is an optional integration with Replicate's model API. It is not an on-device model and it does not provide a general-purpose cybersecurity scanner. Replicate model predictions may incur charges; check your Replicate account's pricing and limits before approving calls.

In Termux:

    cd Yasser-Security-Lab/mcp-bridge
    bash setup-termux.sh

The setup script asks for a Replicate API token with hidden input, generates a separate local bridge token, and stores both in `mcp-bridge/.env` with owner-only file permissions. Do not commit or share that file.

Start the bridge:

    set -a
    source .env
    set +a
    npm start

It listens only on `127.0.0.1:8765`. In the Android app's Replicate MCP panel, enter the local bridge token printed by the setup script and tap **Discover tools**. Choose a tool, supply JSON arguments, review them, and check the approval box before calling it. Every tool call is an explicit user-approved operation.

The app talks to the bridge over loopback. The bridge launches the official `replicate-mcp` stdio server and keeps the Replicate credential out of the APK and the HTTP request body.

## 3. Security constraints

- Never bind the bridge to `0.0.0.0` or expose port 8765 publicly.
- Do not paste the Replicate token into the Android app. Only the separate local bridge token belongs in the app.
- Tool calls may create cloud predictions and may consume paid credits.
- The local LLM is advisory. Its output is untrusted; inspect any code or command it proposes.
- Keep an explicit human approval step before any tool execution or repository mutation.
- The Termux processes must remain running while the Android app uses the local model or MCP bridge.

## References

- Replicate MCP: https://replicate.com/docs/reference/mcp
- Replicate hosted MCP quick-start: https://mcp.replicate.com/
- llama.cpp Android/Termux guide: https://github.com/ggml-org/llama.cpp/blob/master/docs/android.md
- Qwen2.5-Coder 0.5B GGUF: https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF
