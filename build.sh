#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Detecting GPU architecture..."
GPU_NAME=$(nvidia-smi --query-gpu=gpu_name --format=csv,noheader 2>/dev/null | head -1 || echo "unknown")
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

echo "==> Compiling CUDA kernel + wrapper ($SM_ARCH)..."
nvcc -shared -Xcompiler -fPIC \
    -arch=$SM_ARCH \
    -O3 \
    --use_fast_math \
    -o libcuopc.so \
    kernel.cu wrapper.cu \
    -lcudart

echo "==> Detecting CUDA library path..."
CUDA_LIB_DIR=$(dirname "$(find /usr/local/cuda* /usr/lib* -name 'libcudart.so' 2>/dev/null | head -1)" 2>/dev/null || true)
if [ -z "$CUDA_LIB_DIR" ] || [ "$CUDA_LIB_DIR" = "." ]; then
    CUDA_LIB_DIR="/usr/local/cuda/lib64"
fi
echo "    CUDA libs: $CUDA_LIB_DIR"

echo "==> Building Go binary with CGO..."
CGO_CFLAGS="-I$(pwd)" \
CGO_LDFLAGS="-L$(pwd) -L${CUDA_LIB_DIR} -lcuopc -lcudart -Wl,-rpath,$(pwd) -Wl,-rpath,${CUDA_LIB_DIR}" \
go build -o cuopc main.go

echo "==> Done."
echo "    LD_LIBRARY_PATH=$(pwd):${CUDA_LIB_DIR} ./cuopc -test"
echo "    LD_LIBRARY_PATH=$(pwd):${CUDA_LIB_DIR} ./cuopc -first=<8hex> -last=<8hex> -bits=33"
