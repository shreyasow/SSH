#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crypto.h"
#include "rsa.h"

#define PORT 8080

int main()
{
    int server_fd, client_fd;
    struct sockaddr_in addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket failed");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("bind failed");
        return 1;
    }

    listen(server_fd, 1);
    printf("Server waiting...\n");

    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0)
    {
        perror("accept failed");
        return 1;
    }

    FILE *fp = fopen("server_public.pem", "rb");
    if (!fp)
    {
        perror("public key open failed");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long key_size = ftell(fp);
    rewind(fp);

    char *pubkey = malloc(key_size);
    if (!pubkey)
    {
        perror("malloc failed");
        return 1;
    }

    fread(pubkey, 1, key_size, fp);
    fclose(fp);

    send(client_fd, &key_size, sizeof(key_size), 0);
    send(client_fd, pubkey, key_size, 0);

    free(pubkey);

    int enc_len;
    if (recv_all(client_fd, &enc_len, sizeof(int)) <= 0)
    {
        printf("Failed to receive enc_len\n");
        return 1;
    }

    unsigned char enc_key[512];
    if (recv_all(client_fd, enc_key, enc_len) <= 0)
    {
        printf("Failed to receive enc_key\n");
        return 1;
    }

    EVP_PKEY *priv_key = NULL;
    if (!load_private_key("server_private.pem", &priv_key))
    {
        printf("Failed to load private key\n");
        return 1;
    }

    unsigned char session_key[32];

    int dec_len = rsa_decrypt(priv_key, enc_key, enc_len, session_key);

    if (dec_len != 32)
    {
        printf("RSA decrypt failed\n");
        return 1;
    }

    printf("Session key established successfully\n");

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];

    int cipher_len;
    unsigned char ciphertext[BUF_SIZE];
    unsigned char plaintext[BUF_SIZE];

    recv_all(client_fd, nonce, NONCE_SIZE);
    recv_all(client_fd, tag, TAG_SIZE);
    recv_all(client_fd, &cipher_len, sizeof(int));
    recv_all(client_fd, ciphertext, cipher_len);

    int len = decrypt(ciphertext, cipher_len, tag, session_key, nonce, plaintext);

    if (len > 0)
    {
        plaintext[len] = '\0';
        printf("Decrypted: %s\n", plaintext);
    }
    else
    {
        printf("Decryption failed!\n");
    }

    EVP_PKEY_free(priv_key);    
    close(client_fd);
    close(server_fd);

    return 0;
}
