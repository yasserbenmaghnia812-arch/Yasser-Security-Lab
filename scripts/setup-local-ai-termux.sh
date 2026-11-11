#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

ROOT="$HOME/llama.cpp"
MODEL_DIR="$HOME/models"
MODEL="$MODEL_DIR/qwen2.5-coder-0.5b-instruct-q4_0.gguf"
MODEL_URL="https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-0.5b-instruct-q4_0.gguf"

pkg update -y
pkg install -y git cmake clang make libandroid-spawn curl

if [ ! -d "$ROOT/.git" ]; then
  git clone --depth 1 https://github.com/ggml-org/llama.cpp "$ROOT"
fi

cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release -DGGML_OPENMP=OFF
cmake --build "$ROOT/build" --config Release -j 2 --target llama-server

mkdir -p "$MODEL_DIR"
if [ ! -s "$MODEL" ]; then
  curl --fail --location --retry 3 "$MODEL_URL" -o "$MODEL"
fi

printf '\nLocal code model is installed. Model file:\n%s\n' "$MODEL"
printf '\nStart the local OpenAI-compatible inference server with:\n'
printf '  "%s/build/bin/llama-server" -m "%s" --alias yasser-coder-0.5b --host 127.0.0.1 --port 11434 -c 1024 -t 4 -b 128\n' "$ROOT" "$MODEL"
