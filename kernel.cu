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

static const char HEX[] = "0123456789abcdef";
static const char YCHARS[] = "89ab";

// UUID v4 layout (36 chars):
//   pos  0-7:   first 8 hex (FIXED, parameter)
//   pos  8:     '-'
//   pos  9-12:  4 hex (variable)   ← nonce bits 0-15
//   pos 13:     '-'
//   pos 14:     '4' (FIXED, version)
//   pos 15-17:  3 hex (variable)   ← nonce bits 16-27
//   pos 18:     '-'
//   pos 19:     y = 8/9/a/b        ← nonce bits 28-29 (2 bits)
//   pos 20-23:  4 hex (variable)   ← nonce bits 30-45
//   pos 24:     '-'
//   pos 25-27:  3 hex (variable)   ← nonce bits 46-57
//   pos 28-35:  last 8 hex (FIXED, parameter)
//
// Total: 60 bits of entropy (2^60 >> 2^33 needed)

__device__ __forceinline__ void build_uuid(
    uint64_t n,
    const char* __restrict__ first8,
    const char* __restrict__ last8,
    char* __restrict__ u)
{
    u[0]  = first8[0]; u[1]  = first8[1]; u[2]  = first8[2]; u[3]  = first8[3];
    u[4]  = first8[4]; u[5]  = first8[5]; u[6]  = first8[6]; u[7]  = first8[7];
    u[8]  = '-';

    u[9]  = HEX[(n >> 0)  & 0xF];
    u[10] = HEX[(n >> 4)  & 0xF];
    u[11] = HEX[(n >> 8)  & 0xF];
    u[12] = HEX[(n >> 12) & 0xF];
    u[13] = '-';

    u[14] = '4';
    u[15] = HEX[(n >> 16) & 0xF];
    u[16] = HEX[(n >> 20) & 0xF];
    u[17] = HEX[(n >> 24) & 0xF];
    u[18] = '-';

    u[19] = YCHARS[(n >> 28) & 0x3];
    u[20] = HEX[(n >> 30) & 0xF];
    u[21] = HEX[(n >> 34) & 0xF];
    u[22] = HEX[(n >> 38) & 0xF];
    u[23] = HEX[(n >> 42) & 0xF];
    u[24] = '-';

    u[25] = HEX[(n >> 46) & 0xF];
    u[26] = HEX[(n >> 50) & 0xF];
    u[27] = HEX[(n >> 54) & 0xF];
    u[28] = last8[0]; u[29] = last8[1]; u[30] = last8[2]; u[31] = last8[3];
    u[32] = last8[4]; u[33] = last8[5]; u[34] = last8[6]; u[35] = last8[7];
}

__device__ __forceinline__ void sha512_single(const char* __restrict__ msg, uint64_t* __restrict__ out) {
    uint64_t W[16];
    W[0]  = ((uint64_t)msg[0]  << 56) | ((uint64_t)msg[1]  << 48) |
            ((uint64_t)msg[2]  << 40) | ((uint64_t)msg[3]  << 32) |
            ((uint64_t)msg[4]  << 24) | ((uint64_t)msg[5]  << 16) |
            ((uint64_t)msg[6]  << 8)  | (uint64_t)msg[7];
    W[1]  = ((uint64_t)msg[8]  << 56) | ((uint64_t)msg[9]  << 48) |
            ((uint64_t)msg[10] << 40) | ((uint64_t)msg[11] << 32) |
            ((uint64_t)msg[12] << 24) | ((uint64_t)msg[13] << 16) |
            ((uint64_t)msg[14] << 8)  | (uint64_t)msg[15];
    W[2]  = ((uint64_t)msg[16] << 56) | ((uint64_t)msg[17] << 48) |
            ((uint64_t)msg[18] << 40) | ((uint64_t)msg[19] << 32) |
            ((uint64_t)msg[20] << 24) | ((uint64_t)msg[21] << 16) |
            ((uint64_t)msg[22] << 8)  | (uint64_t)msg[23];
    W[3]  = ((uint64_t)msg[24] << 56) | ((uint64_t)msg[25] << 48) |
            ((uint64_t)msg[26] << 40) | ((uint64_t)msg[27] << 32) |
            ((uint64_t)msg[28] << 24) | ((uint64_t)msg[29] << 16) |
            ((uint64_t)msg[30] << 8)  | (uint64_t)msg[31];
    W[4]  = ((uint64_t)msg[32] << 56) | ((uint64_t)msg[33] << 48) |
            ((uint64_t)msg[34] << 40) | ((uint64_t)msg[35] << 32) |
            0x0000008000000000ULL;
    W[5] = 0;  W[6] = 0;  W[7] = 0;
    W[8] = 0;  W[9] = 0;  W[10] = 0; W[11] = 0;
    W[12] = 0; W[13] = 0; W[14] = 0;
    W[15] = 288ULL;

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

    char uuid[36];
    build_uuid(nonce, first8, last8, uuid);

    uint64_t H[2];
    sha512_single(uuid, H);

    // First 33 bits of hash: H[0] covers bits 0-63
    // Need bits 0-31 all zero AND bit 32 zero
    // (H[0] >> 31) == 0 checks that the top 33 bits of H[0] are zero
    if ((H[0] >> 31) == 0) {
        if (atomicCAS(g_found, 0, 1) == 0) {
            *g_result_nonce = nonce;
            __threadfence();
        }
    }
}

__global__ void sha512_test_kernel(const char* __restrict__ input, uint64_t* __restrict__ out_H0) {
    char msg[36];
    for (int i = 0; i < 36; i++) msg[i] = input[i];

    uint64_t H[2];
    sha512_single(msg, H);
    *out_H0 = H[0];
}
