#ifndef ARGON2_H
#define ARGON2_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum Argon2_type { Argon2_d = 0, Argon2_i = 1, Argon2_id = 2 } argon2_type;

/* ARGON2_OK is guaranteed to be 0 by the real libargon2 headers as well;
 * defined here since this compat header doesn't pull in the full error
 * enum. */
#define ARGON2_OK 0
int argon2id_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                       const uint32_t parallelism, const void *pwd,
                       const size_t pwdlen, const void *salt,
                       const size_t saltlen, void *hash,
                       const size_t hashlen);
const char *argon2_error_message(int error_code);
#ifdef __cplusplus
}
#endif
#endif
