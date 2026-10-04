/* Kravyx DLP engine C ABI. See core/ffi/src/lib.rs for the contract.
 * Every function returns a NUL-terminated JSON string that MUST be freed with kx_free(). */
#ifndef KRAVYX_H
#define KRAVYX_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
char *kx_policy_validate(const char *bundle_json);
char *kx_policy_simulate(const char *bundle_json, const char *context_json,
                         const uint8_t *content, size_t content_len, int64_t now_unix);
char *kx_engine_info(void);
void  kx_free(char *p);
#ifdef __cplusplus
}
#endif
#endif
