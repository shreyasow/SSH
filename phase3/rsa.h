#ifndef RSA_H
#define RSA_H

#include <openssl/pem.h>
#include <openssl/rsa.h>

int load_public_key(const char *file, EVP_PKEY **key);
int load_private_key(const char *file, EVP_PKEY **key);

int rsa_encrypt(EVP_PKEY *pub, unsigned char *in, int inlen, unsigned char *out);

int rsa_decrypt(EVP_PKEY *priv, unsigned char *in, int inlen, unsigned char *out);

#endif
