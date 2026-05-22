#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define BUF_SIZE 1024

extern unsigned char KEY[32];

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext, unsigned char *tag);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *nonce, unsigned char *plaintext);

int recv_all(int sock, void *buf, int len);

#endif#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define BUF_SIZE 1024

extern unsigned char KEY[32];

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *nonce, unsigned char *ciphertext, unsigned char *tag);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *nonce, unsigned char *plaintext);

int recv_all(int sock, void *buf, int len);

#endif
