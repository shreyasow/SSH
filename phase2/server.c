#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crypto.h"

#define PORT 8080

int main()
{
    int server_fd, client_fd;
    struct sockaddr_in addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);

    printf("Server waiting...\n");

    client_fd = accept(server_fd, NULL, NULL);

    unsigned char nonce[NONCE_SIZE];
    unsigned char tag[TAG_SIZE];
    int cipher_len;

    unsigned char ciphertext[BUF_SIZE];
    unsigned char plaintext[BUF_SIZE];

    recv_all(client_fd, nonce, NONCE_SIZE);
    recv_all(client_fd, tag, TAG_SIZE);
    recv_all(client_fd, &cipher_len, sizeof(int));
    recv_all(client_fd, ciphertext, cipher_len);

    int len = decrypt(ciphertext, cipher_len, tag, KEY, nonce, plaintext);

    if (len > 0)
    {
        plaintext[len] = '\0';
        printf("Decrypted: %s\n", plaintext);
    }
    else
    {
        printf("Decryption failed!\n");
    }

    close(client_fd);
    close(server_fd);
}
