#include <stdint.h>
#include <string.h>

static const __constant__ uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define BSIG1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SSIG0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SSIG1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static const __constant__ char HEX[] = "0123456789abcdef";
static const __constant__ char YCHARS[] = "89ab";

// UUID v4 raw 16 bytes:
//   bytes 0-3:   fixed (from first8 hex string)
//   bytes 4-5:   variable from nonce bits 0-15
//   byte  6:     0x40 | nonce[19:16]  (version 4 + 4 variable bits)
//   byte  7:     nonce[27:20]
//   byte  8:     0x80 | nonce[33:28]  (variant 10 + 6 variable bits)
//   bytes 9-11:  nonce[57:34]
//   bytes 12-15: fixed (from last8 hex string)

__device__ __forceinline__ void build_uuid_raw(
    uint64_t n,
    const char* __restrict__ first8,
    const char* __restrict__ last8,
    char* __restrict__ raw)
{
    for (int i = 0; i < 4; i++) {
        uint8_t hi = first8[i * 2];
        uint8_t lo = first8[i * 2 + 1];
        hi = (hi >= 'a') ? (hi - 'a' + 10) : (hi - '0');
        lo = (lo >= 'a') ? (lo - 'a' + 10) : (lo - '0');
        raw[i] = (hi << 4) | lo;
    }

    raw[4] = (n >> 8) & 0xFF;
    raw[5] = n & 0xFF;
    raw[6] = 0x40 | ((n >> 16) & 0x0F);
    raw[7] = (n >> 20) & 0xFF;
    raw[8] = 0x80 | ((n >> 28) & 0x3F);
    raw[9]  = (n >> 34) & 0xFF;
    raw[10] = (n >> 42) & 0xFF;
    raw[11] = (n >> 50) & 0xFF;

    for (int i = 0; i < 4; i++) {
        uint8_t hi = last8[i * 2];
        uint8_t lo = last8[i * 2 + 1];
        hi = (hi >= 'a') ? (hi - 'a' + 10) : (hi - '0');
        lo = (lo >= 'a') ? (lo - 'a' + 10) : (lo - '0');
        raw[12 + i] = (hi << 4) | lo;
    }
}

__device__ __forceinline__ void sha512_16bytes(const char* __restrict__ raw16, uint64_t* __restrict__ out) {
    uint64_t W[16];
    W[0]  = ((uint64_t)(uint8_t)raw16[0]  << 56) | ((uint64_t)(uint8_t)raw16[1]  << 48) |
            ((uint64_t)(uint8_t)raw16[2]  << 40) | ((uint64_t)(uint8_t)raw16[3]  << 32) |
            ((uint64_t)(uint8_t)raw16[4]  << 24) | ((uint64_t)(uint8_t)raw16[5]  << 16) |
            ((uint64_t)(uint8_t)raw16[6]  << 8)  | (uint64_t)(uint8_t)raw16[7];
    W[1]  = ((uint64_t)(uint8_t)raw16[8]  << 56) | ((uint64_t)(uint8_t)raw16[9]  << 48) |
            ((uint64_t)(uint8_t)raw16[10] << 40) | ((uint64_t)(uint8_t)raw16[11] << 32) |
            ((uint64_t)(uint8_t)raw16[12] << 24) | ((uint64_t)(uint8_t)raw16[13] << 16) |
            ((uint64_t)(uint8_t)raw16[14] << 8)  | (uint64_t)(uint8_t)raw16[15];
    W[2]  = 0x8000000000000000ULL;
    W[3] = 0;  W[4] = 0;  W[5] = 0;  W[6] = 0;
    W[7] = 0;  W[8] = 0;  W[9] = 0;  W[10] = 0;
    W[11] = 0; W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 128ULL;

    uint64_t a = 0x6a09e667f3bcc908ULL, b = 0xbb67ae8584caa73bULL;
    uint64_t c = 0x3c6ef372fe94f82bULL, d = 0xa54ff53a5f1d36f1ULL;
    uint64_t e = 0x510e527fade682d1ULL, f = 0x9b05688c2b3e6c1fULL;
    uint64_t g = 0x1f83d9abfb41bd6bULL, h = 0x5be0cd19137e2179ULL;

    #pragma unroll
    for (int t = 0; t < 16; t++) {
        uint64_t T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + W[t];
        uint64_t T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    for (int t = 16; t < 80; t++) {
        uint64_t w = SSIG1(W[(t-2)&15]) + W[(t-7)&15] + SSIG0(W[(t-15)&15]) + W[t&15];
        W[t&15] = w;
        uint64_t T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + w;
        uint64_t T2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    out[0] = 0x6a09e667f3bcc908ULL + a;
    out[1] = 0xbb67ae8584caa73bULL + b;
}

__global__ void __launch_bounds__(256, 4)
sha512_cracker_kernel(
    uint64_t base_nonce,
    const char* __restrict__ first8,
    const char* __restrict__ last8,
    uint64_t* __restrict__ g_result_nonce,
    int* __restrict__ g_found)
{
    if (*g_found) return;

    uint64_t nonce = base_nonce + (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;

    char raw[16];
    build_uuid_raw(nonce, first8, last8, raw);

    uint64_t H[2];
    sha512_16bytes(raw, H);

    if ((H[0] >> 31) == 0) {
        if (atomicCAS(g_found, 0, 1) == 0) {
            *g_result_nonce = nonce;
            __threadfence();
        }
    }
}

__global__ void sha512_test_kernel(const char* __restrict__ input, uint64_t* __restrict__ out_H0) {
    char raw[16];
    for (int i = 0; i < 16; i++) raw[i] = input[i];

    uint64_t H[2];
    sha512_16bytes(raw, H);
    *out_H0 = H[0];
}
