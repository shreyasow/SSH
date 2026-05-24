#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "crypto.h"
#include "rsa.h"

int main()
{
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    long key_size;
    recv_all(sock, &key_size, sizeof(key_size));

    char *pubkey = malloc(key_size);
    recv_all(sock, pubkey, key_size);

    BIO *bio = BIO_new_mem_buf(pubkey, key_size);
    EVP_PKEY *server_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!server_pubkey)
    {
        printf("Failed to parse public key\n");
        return 1;
    }
    BIO_free(bio);
    free(pubkey);

    unsigned char session_key[32];
    unsigned char enc_key[512];

    RAND_bytes(session_key, 32);

    int enc_len = rsa_encrypt(server_pubkey, session_key, 32, enc_key);

    send(sock, &enc_len, sizeof(enc_len), 0);
    send(sock, enc_key, enc_len, 0);

    printf("Session key sent securely\n");

    unsigned char *msg = (unsigned char *)"Hello Secure World!";
    unsigned char ciphertext[BUF_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char nonce[NONCE_SIZE];

    RAND_bytes(nonce, NONCE_SIZE);

    int cipher_len = encrypt(msg, strlen((char*)msg), session_key, nonce, ciphertext, tag);

    send(sock, nonce, NONCE_SIZE, 0);
    send(sock, tag, TAG_SIZE, 0);
    send(sock, &cipher_len, sizeof(int), 0);
    send(sock, ciphertext, cipher_len, 0);

    close(sock);
    return 0;
}
