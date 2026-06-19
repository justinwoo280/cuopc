#include "wrapper.h"
#include <cuda_runtime.h>
#include <stdio.h>
#include <string.h>

extern __global__ void sha512_cracker_kernel(
    uint64_t base_nonce,
    const char* first8,
    const char* last8,
    uint64_t* g_result_nonce,
    int* g_found);

extern __global__ void sha512_test_kernel(
    const char* input,
    uint64_t* out_H0);

static uint64_t* d_result_nonce = NULL;
static int*      d_found        = NULL;
static char*     d_first8       = NULL;
static char*     d_last8        = NULL;

extern "C" int init_cracker(const char* first8, const char* last8) {
    cudaError_t err;

    err = cudaMalloc(&d_result_nonce, sizeof(uint64_t));
    if (err != cudaSuccess) { fprintf(stderr, "cudaMalloc result: %s\n", cudaGetErrorString(err)); return -1; }

    err = cudaMalloc(&d_found, sizeof(int));
    if (err != cudaSuccess) { fprintf(stderr, "cudaMalloc found: %s\n", cudaGetErrorString(err)); return -1; }

    err = cudaMalloc(&d_first8, 8);
    if (err != cudaSuccess) { fprintf(stderr, "cudaMalloc first8: %s\n", cudaGetErrorString(err)); return -1; }

    err = cudaMalloc(&d_last8, 8);
    if (err != cudaSuccess) { fprintf(stderr, "cudaMalloc last8: %s\n", cudaGetErrorString(err)); return -1; }

    uint64_t sentinel = 0xFFFFFFFFFFFFFFFFULL;
    int zero = 0;
    cudaMemcpy(d_result_nonce, &sentinel, sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_found, &zero, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_first8, first8, 8, cudaMemcpyHostToDevice);
    cudaMemcpy(d_last8, last8, 8, cudaMemcpyHostToDevice);

    return 0;
}

extern "C" int launch_kernel(uint64_t base_nonce, uint32_t num_blocks, uint32_t threads_per_block) {
    sha512_cracker_kernel<<<num_blocks, threads_per_block>>>(
        base_nonce, d_first8, d_last8, d_result_nonce, d_found);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        fprintf(stderr, "Kernel launch error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    return 0;
}

extern "C" int poll_result(uint64_t* result_nonce) {
    int found = 0;
    cudaMemcpy(&found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
    if (found) {
        cudaMemcpy(result_nonce, d_result_nonce, sizeof(uint64_t), cudaMemcpyDeviceToHost);
        return 1;
    }
    return 0;
}

extern "C" void cleanup_cracker(void) {
    if (d_result_nonce) cudaFree(d_result_nonce);
    if (d_found)        cudaFree(d_found);
    if (d_first8)       cudaFree(d_first8);
    if (d_last8)        cudaFree(d_last8);
    d_result_nonce = NULL;
    d_found        = NULL;
    d_first8       = NULL;
    d_last8        = NULL;
}

extern "C" uint64_t test_sha512_gpu(const char* input_16) {
    char* d_input = NULL;
    uint64_t* d_H0 = NULL;
    uint64_t h0 = 0;

    cudaMalloc(&d_input, 16);
    cudaMalloc(&d_H0, 2 * sizeof(uint64_t));
    cudaMemcpy(d_input, input_16, 16, cudaMemcpyHostToDevice);

    sha512_test_kernel<<<1, 1>>>(d_input, d_H0);
    cudaDeviceSynchronize();

    cudaMemcpy(&h0, d_H0, sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaFree(d_input);
    cudaFree(d_H0);
    return h0;
}
