#include <main.h>

// Write README
// MakeFile for passing client and server commands
void init_ctr(ctr_state *state, unsigned char *IV) {
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec, 0, AES_BLOCK_SIZE);
    memcpy(state->ivec, IV, 8);
}

int encrypt_decrypt_data(char *inbuf, char *outbuf, int num_bytes, char *key, unsigned char *IV, int mode, ctr_state *state) {
    AES_KEY E_D_Key;
    unsigned char plain_text_buffer[AES_BLOCK_SIZE];
    unsigned char cipher_text_buffer[AES_BLOCK_SIZE];

    if (AES_set_encrypt_key((const unsigned char *)key, ENCRYPTION_LENGTH, &E_D_Key) < 0) {
        perror("Cannot set encryption key ");
        return -1;
    }

    int pt_size = 0;
    int inbuf_size = num_bytes;
    int outbuf_size = 0;
    int i = 0, j = 0;
    while(inbuf_size > 0) {
        //Taking 16 bytes from input buffer and loading it in plain text buffer for encryption
        for (i = pt_size; (i < pt_size + AES_BLOCK_SIZE) && (i < num_bytes); i++) {
            plain_text_buffer[i - pt_size] = inbuf[i];
        }
        
        AES_ctr128_encrypt(plain_text_buffer, cipher_text_buffer, i - pt_size, &E_D_Key, state->ivec, state->ecount, &(state->num));

        for (j = 0; j < i - pt_size; j++) {
            outbuf[outbuf_size++] = cipher_text_buffer[j];
        }

        pt_size += i - pt_size;
        inbuf_size -= AES_BLOCK_SIZE;
    }
    
    return outbuf_size;
}

void *server_read_from_sshd(void *arg) {
    socketData *sData = (socketData *)arg;
    unsigned char IV[AES_BLOCK_SIZE];
    char inbuf[MAX_NUMBER_OF_BYTES];
    char outbuf[MAX_NUMBER_OF_BYTES];
    int server_fd = sData->server_fd;
    int client_fd = sData->client_fd;
    char *key = sData->key;
    int random_fd;
    int num_bytes;

    /* Request /dev/urandom for randomly generated IV */
    if ((random_fd = open("/dev/urandom", O_RDONLY)) < 0) {
        perror("Cannot get random number ");
        close(client_fd);
        return NULL;
    }

    if (read(random_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Reading random numbers failed ");
        close(client_fd);
        return NULL;
    }
    /* Read /dev/urandom for randomly generated IV success */

    if (write(client_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Writing random numbers to socket failed ");
        close(client_fd);
        return NULL;
    }

	ctr_state e_state;
	init_ctr(&e_state, IV);

    while (1) {
        memset(inbuf, 0, MAX_NUMBER_OF_BYTES);
        if ((num_bytes = read(server_fd, inbuf, MAX_NUMBER_OF_BYTES)) <= 0) {
            perror("Cannot read data from sshd server ");
            close(server_fd);
            close(client_fd);
            return NULL;
        }

        int E_D_length = encrypt_decrypt_data(inbuf, outbuf, num_bytes, key, IV, ENCRYPT_MODE, &e_state);

        if (write(client_fd, outbuf, E_D_length) <= 0) {
            perror("Cannot write data to proxy-client ");
            close(server_fd);
            close(client_fd);
            return NULL;
        }
    }
}

void *server_write_to_sshd(void *arg) {
    socketData *sData = (socketData *)arg;
    unsigned char IV[AES_BLOCK_SIZE];
    char inbuf[MAX_NUMBER_OF_BYTES];
    char outbuf[MAX_NUMBER_OF_BYTES];
    int server_fd = sData->server_fd;
    int client_fd = sData->client_fd;
    char *key = sData->key;
    int num_bytes;

    if (read(client_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Reading IV failed ");
        close(client_fd);
        return NULL;
    }

	ctr_state d_state;
	init_ctr(&d_state, IV);

    while (1) {
        memset(inbuf, 0, MAX_NUMBER_OF_BYTES);
        if ((num_bytes = read(client_fd, inbuf, MAX_NUMBER_OF_BYTES)) <= 0) {
            perror("Cannot read data from proxy-client ");
            close(client_fd);
            close(server_fd);
            return NULL;
        }

        int E_D_length = encrypt_decrypt_data(inbuf, outbuf, num_bytes, key, IV, DECRYPT_MODE, &d_state);
        
        if (write(server_fd, outbuf, E_D_length) <= 0) {
            perror("Cannot write data to shhd server ");
            close(client_fd);
            close(server_fd);
            return NULL;
        }
    }
}

void parse_client_connections(int client_fd, char *dest, int port, char *key) {
    // client_fd -> File Descriptor of accepted client connection
    struct sockaddr_in server_addr;
    int server_fd;
    struct hostent *host;
    char host_name[IP_ADDRESS_LENGTH];
    pthread_t thread_read, thread_write;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket connection ");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    host = gethostbyname(dest);

    if (host == NULL) {
        perror("Cannot resolve host name ");
        return;
    }

    strcpy(host_name, inet_ntoa(*(struct in_addr *)host->h_addr));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(host_name);
    
    if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Cannot connect to sshd server ");
        close(client_fd);
        return;
    }

    socketData *sData = (socketData *)malloc(sizeof(socketData));
    sData->client_fd = client_fd;
    sData->server_fd = server_fd;
    sData->key = key;

    // Socket1 -> Socket2
    if (pthread_create(&thread_write, NULL, server_write_to_sshd, sData)) {
        perror("Unable to create new thread ");
        close(client_fd);
        exit(1);
    }

    // Socket2 -> Socket1
    if (pthread_create(&thread_read, NULL, server_read_from_sshd, sData)) {
        perror("Unable to create new thread ");
        close(client_fd);
        exit(1);
    }
    pthread_join(thread_write, NULL);
    pthread_join(thread_read, NULL);

    IF_FREE(sData);
    close(server_fd);
    close(client_fd);
}

void establish_server_connection(int local_port, char *dest, int port, char *key) {
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int server_fd;
    int client_fd;
    int options = 1;

    // Socket1
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket connection ");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &options, sizeof(options))) {
        perror("Failed to set options on Socket ");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(local_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Address already in use. Cannot bind address to socket ");
        close(server_fd);
        return;
    }

    listen(server_fd, MAX_NUMBER_OF_SOCKET_CONNECTIONS);

    unsigned int client_addr_len = sizeof(client_addr);
    while ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len)) > 0) {
        perror("Client connection received ");
        int pid = fork();
        if (pid < 0) {
            perror("Cannot fork a child ");
            return;
        } else if (pid == 0) {
            // Child
            parse_client_connections(client_fd, dest, port, key);
            return;
        }
        //Parent
    }

    perror("Cannot accept any new connections ");
    close(server_fd);
}

void *client_write_to_stdout(void *arg) {
    socketData *sData = (socketData *)arg;
    unsigned char IV[AES_BLOCK_SIZE];
    char inbuf[MAX_NUMBER_OF_BYTES];
    char outbuf[MAX_NUMBER_OF_BYTES];
    int client_fd = sData->client_fd;
    char *key = sData->key;
    int num_bytes;

    if (read(client_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Reading IV failed ");
        close(client_fd);
        exit(1);
    }

	ctr_state d_state;
	init_ctr(&d_state, IV);

    while (1) {
        memset(inbuf, 0, MAX_NUMBER_OF_BYTES);
        if ((num_bytes = read(client_fd, inbuf, MAX_NUMBER_OF_BYTES)) <= 0) {
            perror("Cannot read data from sshd server ");
            close(client_fd);
            return NULL;
        }

        int E_D_length = encrypt_decrypt_data(inbuf, outbuf, num_bytes, key, IV, DECRYPT_MODE, &d_state);

        if (write(STDOUT_FILENO, outbuf, E_D_length) <= 0) {
            perror("Cannot write data to STDOUT ");
            close(client_fd);
            return NULL;
        }
    }
}

void *client_read_from_stdin(void *arg) {
    socketData *sData = (socketData *)arg;
    unsigned char IV[AES_BLOCK_SIZE];
    char inbuf[MAX_NUMBER_OF_BYTES];
    char outbuf[MAX_NUMBER_OF_BYTES];
    int client_fd = sData->client_fd;
    char *key = sData->key;
    int random_fd;
    int num_bytes;

    /* Request /dev/urandom for randomly generated IV */
    if ((random_fd = open("/dev/urandom", O_RDONLY)) < 0) {
        perror("Cannot get random number ");
        close(client_fd);
        return NULL;
    }

    if (read(random_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Reading random numbers failed ");
        close(client_fd);
        return NULL;
    }
    /* Read /dev/urandom for randomly generated IV success */

    if (write(client_fd, IV, AES_BLOCK_SIZE) <= 0) {
        perror("Writing random numbers to socket failed ");
        close(client_fd);
        return NULL;
    }

	ctr_state e_state;
	init_ctr(&e_state, IV);

    while (1) {
        memset(inbuf, 0, MAX_NUMBER_OF_BYTES);

        if ((num_bytes = read(STDIN_FILENO, inbuf, MAX_NUMBER_OF_BYTES)) <= 0) {
            perror("Cannot read data from STDIN ");
            close(client_fd);
            return NULL;
        }

        int E_D_length = encrypt_decrypt_data(inbuf, outbuf, num_bytes, key, IV, ENCRYPT_MODE, &e_state);

        if ((write(client_fd, outbuf, E_D_length)) <= 0) {
            perror("Cannot write data to proxy-server ");
            close(client_fd);
            return NULL;
        }
    }
}

void establish_client_connection(char *dest, int port, char *key) {
    struct sockaddr_in client_addr;
    int client_fd = 0;
    struct hostent *host;
    char host_name[IP_ADDRESS_LENGTH];
    pthread_t thread_read, thread_write;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Cannot create socket connection ");
        return;
    }

    memset(&client_addr, 0, sizeof(client_addr));

    host = gethostbyname(dest);
    if (host == NULL) {
        perror("Cannot resolve host name ");
        return;
    }
    strcpy(host_name, inet_ntoa(*(struct in_addr *)host->h_addr));
    
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(port);
    client_addr.sin_addr.s_addr = inet_addr(host_name);
    
    if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Cannot connect to proxy-server ");
        return;
    }

    socketData *sData = (socketData *)malloc(sizeof(socketData));
    sData->server_fd = 0;
    sData->client_fd = client_fd;
    sData->key = key;
    
    // STDIN -> Socket1
    if (pthread_create(&thread_read, NULL, client_read_from_stdin, sData)) {
        perror("Unable to create new thread ");
        return;
    }

    // Socket1 -> STDOUT
    if (pthread_create(&thread_write, NULL, client_write_to_stdout, sData)) {
        perror("Unable to create new thread ");
        return;
    }

    pthread_join(thread_read, NULL);
    pthread_join(thread_write, NULL);

    close(client_fd);
}

int main(int argc, char *argv[]) {
    char *dest = NULL;
    char *key = NULL;
    int port = 0;
    int local_port = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i] && !strncmp(argv[i], "-l", OPTIONS_LENGTH)) {
            if (argv[i + 1] && !strncmp(argv[i + 1], "-", OPTIONS_LENGTH - 1)) {
                printf("Unidentified format ");
                printf("Format is : pbproxy [-l port] [-k keyfile] destination port ");
                return 0;
            }
            local_port = atoi(argv[i+1]);
            i++;
        } else if (argv[i] && !strncmp(argv[i], "-k", OPTIONS_LENGTH)) {
            if (argv[i + 1] && !strncmp(argv[i + 1], "-", OPTIONS_LENGTH - 1)) {
                printf("Unidentified format ");
                printf("Format is : pbproxy [-l port] [-k keyfile] destination port ");
                return 0;
            }
            key = strdup(argv[i + 1]);
            i++;
        } else {
            dest = strdup(argv[i]);
            if (argv[i + 1]) {
                port = atoi(argv[i + 1]);
            } else {
                printf("Unidentified format ");
                printf("Either Destination is invalid or port is invalid ");
                printf("Format is : pbproxy [-l port] [-k keyfile] destination port ");
                return 0;
            }
            i++;
        }
    }

    char *sym_key = (char *)malloc(KEY_LENGTH * sizeof(char));
    struct stat file_status;
    if (stat(key, &file_status) == 0) {
		fprintf(stderr, "Opening file %s ", key);
		perror("");

        FILE *fp = fopen(key, "r");
        char ch;
        int index = 0;
        if (fp == NULL) {
            perror("Invalid Key File ");
            return 0;
        }
        while ((ch = fgetc(fp)) != EOF) {
            sym_key[index++] = ch;
        }
        fclose(fp);
    } else if (key == NULL) {
		perror("No key specified. Choosing own key ");
        strcpy(sym_key, SYMMETRIC_KEY);
    } else {
		fprintf(stderr, "Key provided in plain-text. %s ", key);
		perror("");

        IF_FREE(sym_key);
        sym_key = strdup(key);
    }

    if (local_port != 0) {
        establish_server_connection(local_port, dest, port, sym_key);
    } else {
        establish_client_connection(dest, port, sym_key);
    }

    return 0;
}
