#!/bin/bash
# Colab build & run script
# 1. Upload the cuopc/ directory to /content/cuopc on Colab
# 2. Usage:
#    !bash /content/cuopc/colab_run.sh -test                        # GPU SHA-512 self-test
#    !bash /content/cuopc/colab_run.sh -first=abcd1234 -last=ca010150 -bits=33

set -euo pipefail

WORKDIR="/content/cuopc"
cd "$WORKDIR"

echo "==> Checking GPU..."
nvidia-smi --query-gpu=name,compute_cap --format=csv,noheader || { echo "No GPU!"; exit 1; }

echo "==> Checking Go..."
which go >/dev/null 2>&1 || {
    apt-get update -qq && apt-get install -y -qq golang-go
}
go version

echo "==> Detecting GPU architecture..."
GPU_NAME=$(nvidia-smi --query-gpu=gpu_name --format=csv,noheader | head -1)
echo "    GPU: $GPU_NAME"

case "$GPU_NAME" in
    *A100*)       SM_ARCH="sm_80" ;;
    *H100*)       SM_ARCH="sm_90" ;;
    *L4*|*L40*)   SM_ARCH="sm_89" ;;
    *T4*)         SM_ARCH="sm_75" ;;
    *V100*)       SM_ARCH="sm_70" ;;
    *A10*|*A30*)  SM_ARCH="sm_86" ;;
    *RTX\ 30*|*A40*|*A5000*) SM_ARCH="sm_86" ;;
    *RTX\ 40*)    SM_ARCH="sm_89" ;;
    *RTX\ 20*|*TITAN\ RTX*) SM_ARCH="sm_75" ;;
    *)
        echo "    Unknown GPU '$GPU_NAME', falling back to sm_70"
        SM_ARCH="sm_70"
        ;;
esac
echo "    Compute capability: $SM_ARCH"
echo ""

echo "==> Compiling CUDA ($SM_ARCH)..."
nvcc -shared -Xcompiler -fPIC \
    -arch=$SM_ARCH \
    -O3 \
    --use_fast_math \
    -o libcuopc.so \
    kernel.cu wrapper.cu \
    -lcudart

echo "==> Building Go binary..."
CGO_CFLAGS="-I$(pwd)" \
CGO_LDFLAGS="-L$(pwd) -lcuopc -lcudart -Wl,-rpath,$(pwd)" \
go build -o cuopc main.go

echo "==> Build complete!"
echo ""

# Pass through any arguments (e.g., -test, -bits=33)
LD_LIBRARY_PATH="$(pwd)" ./cuopc "$@"
