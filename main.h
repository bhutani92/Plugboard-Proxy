#ifndef _MAIN_H
#define _MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/opensslconf.h>
#include <sys/stat.h>
#include <stdbool.h>

#define IP_ADDRESS_LENGTH 16
#define KEY_LENGTH 1024
#define OPTIONS_LENGTH 2
#define MAX_NUMBER_OF_BYTES 4096
#define MAX_NUMBER_OF_SOCKET_CONNECTIONS 5 
#define ENCRYPTION_LENGTH 128
#define SYMMETRIC_KEY "123456789"
#define IF_FREE(x) { \
    if (x) { \
        free(x); \
    } \
}

typedef struct ctr_state {
	unsigned int num;
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned char ecount[AES_BLOCK_SIZE];
} ctr_state;

typedef struct socketData {
    int client_fd;
    int server_fd;
    char *key;
} socketData;

enum {
    ENCRYPT_MODE,
    DECRYPT_MODE
};

#endif
