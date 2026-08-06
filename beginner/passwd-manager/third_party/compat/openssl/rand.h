#ifndef SHIM_OPENSSL_RAND_H
#define SHIM_OPENSSL_RAND_H
#ifdef __cplusplus
extern "C" {
#endif
int RAND_bytes(unsigned char *buf, int num);
#ifdef __cplusplus
}
#endif
#endif
