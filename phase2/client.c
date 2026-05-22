#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include "crypto.h"

#define PORT 8080

int main()
{
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    char *message = "Hello from encrypted client";

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char ciphertext[BUF_SIZE];

    RAND_bytes(nonce, NONCE_SIZE);

    int cipher_len = encrypt((unsigned char*)message, strlen(message), KEY, nonce, ciphertext, tag);

    send(sock, nonce, NONCE_SIZE, 0);
    send(sock, tag, TAG_SIZE, 0);
    send(sock, &cipher_len, sizeof(int), 0);
    send(sock, ciphertext, cipher_len, 0);

    printf("Encrypted message sent\n");

    close(sock);
}
