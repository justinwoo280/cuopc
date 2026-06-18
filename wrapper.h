#ifndef WRAPPER_H
#define WRAPPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int init_cracker(const char* first8, const char* last8);
int launch_kernel(uint64_t base_nonce, uint32_t num_blocks, uint32_t threads_per_block);
int poll_result(uint64_t* result_nonce);
void cleanup_cracker(void);
uint64_t test_sha512_gpu(const char* input_36);

#ifdef __cplusplus
}
#endif

#endif
