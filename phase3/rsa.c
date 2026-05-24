#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int load_public_key(const char *file, EVP_PKEY **key)
{
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;

    *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    return (*key != NULL);
}

int load_private_key(const char *file, EVP_PKEY **key)
{
    FILE *fp = fopen(file, "r");
    if (!fp) return 0;

    *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    return (*key != NULL);
}

int rsa_encrypt(EVP_PKEY *pub, unsigned char *in, int inlen, unsigned char *out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen = 0;

    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}

int rsa_decrypt(EVP_PKEY *priv, unsigned char *in, int inlen, unsigned char *out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen = 0;

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) 
    {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return (int)outlen;
}
