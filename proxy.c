#include "socks5.h"

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int recv_exact(int fd, void *buf, size_t n, int flags) {
    size_t remain = n;
    while (remain > 0) {
        ssize_t recv_len = recv(fd, buf, remain, flags);
        if (recv_len < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                // EINTR: interrupted by system
                // EAGAIN: recv is blocked
                // Try again
                continue;
            } else {
                // Unexpected error
                perror("recv()");
                return -1;
            }
        } else if (recv_len == 0) {
            // No data from socket: disconnected.
            return -1;
        } else {
            // read success
            remain -= recv_len;
            buf += recv_len;
        }
    }
    return 0;
}

int recv_string(int fd, char *str) {
    uint8_t len;
    if (recv_exact(fd, &len, sizeof(uint8_t), 0) != 0) {
        return -1;
    }
    if (recv_exact(fd, str, len, 0) != 0) {
        return -1;
    }
    str[len] = '\0';
    return len;
}

void send_server_hello(int fd, uint8_t method) {
    socks5_server_hello_t server_hello = {
            .version = SOCKS5_VERSION,
            .method = method,
    };
    send(fd, &server_hello, sizeof(socks5_server_hello_t), 0);
}

int handle_greeting(int client_fd) {
    socks5_client_hello_t client_hello;
    if (recv_exact(client_fd, &client_hello, sizeof(socks5_client_hello_t), 0) != 0) {
        return -1;
    }

    if (client_hello.version != SOCKS5_VERSION) {
        fprintf(stderr, "Unsupported socks version %#02x\n", client_hello.version);
        return -1;
    }
    uint8_t methods[UINT8_MAX];
    if (recv_exact(client_fd, methods, client_hello.num_methods, 0) != 0) {
        return -1;
    }
    // Find server auth method in client's list
    int found = 0;
    for (int i = 0; i < (int) client_hello.num_methods; i++) {
        if (methods[i] == SOCKS5_AUTH_NO_AUTH) {
            // Find auth method in client's supported method list
            found = 1;
            break;
        }
    }
    if (!found) {
        // No acceptable method
        fprintf(stderr, "No acceptable method from client\n");
        send_server_hello(client_fd, SOCKS5_AUTH_NOT_ACCEPT);
        return -1;
    }
    // Send auth method choice
    send_server_hello(client_fd, SOCKS5_AUTH_NO_AUTH);
    return 0;
}

void send_domain_reply(int fd, uint8_t reply_type, const char *domain, uint8_t domain_len, in_port_t port) {
    uint8_t buffer[sizeof(uint8_t) + UINT8_MAX + sizeof(in_port_t)];
    uint8_t *ptr = buffer;
    *(socks5_reply_t *) ptr = (socks5_reply_t) {
            .version = SOCKS5_VERSION,
            .reply = reply_type,
            .reserved = 0,
            .addr_type = SOCKS5_ATYP_DOMAIN_NAME
    };
    ptr += sizeof(socks5_reply_t);
    *ptr = domain_len;
    ptr += sizeof(uint8_t);
    memcpy(ptr, domain, domain_len);
    ptr += domain_len;
    *(in_port_t *) ptr = port;
    ptr += sizeof(in_port_t);
    send(fd, buffer, ptr - buffer, 0);
}

void send_ip_reply(int fd, uint8_t reply_type, in_addr_t ip, in_port_t port) {
    uint8_t buffer[sizeof(socks5_reply_t) + sizeof(in_addr_t) + sizeof(in_port_t)];
    uint8_t *ptr = buffer;
    *(socks5_reply_t *) ptr = (socks5_reply_t) {
            .version = SOCKS5_VERSION,
            .reply = reply_type,
            .reserved = 0,
            .addr_type = SOCKS5_ATYP_IPV4
    };
    ptr += sizeof(socks5_reply_t);
    *(in_addr_t *) ptr = ip;
    ptr += sizeof(in_addr_t);
    *(in_port_t *) ptr = port;
    send(fd, buffer, sizeof(buffer), 0);
}

int handle_request(int client_fd) {
    // Handle socks request
    socks5_request_t req;
    if (recv_exact(client_fd, &req, sizeof(socks5_request_t), 0) != 0) {
        return -1;
    }

    if (req.version != SOCKS5_VERSION) {
        fprintf(stderr, "Unsupported socks version %#02x\n", req.version);
        return -1;
    }
    if (req.command != SOCKS5_CMD_CONNECT) {
        fprintf(stderr, "Unsupported command %#02x\n", req.command);
        return -1;
    }

    int remote_fd = -1;
    if (req.addr_type == SOCKS5_ATYP_IPV4) {
        in_addr_t ip;
        if (recv_exact(client_fd, &ip, sizeof(in_addr_t), 0) != 0) {
            return -1;
        }
        in_port_t port;
        if (recv_exact(client_fd, &port, sizeof(in_port_t), 0) != 0) {
            return -1;
        }

        struct sockaddr_in remote_addr;
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = ip;
        remote_addr.sin_port = port;

        remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_fd < 0) {
            perror("socket()");
            send_ip_reply(client_fd, SOCKS5_REP_GENERAL_FAILURE, ip, port);
            return -1;
        }
        if (connect(remote_fd, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) < 0) {
            perror("connect()");
            close(remote_fd);
            send_ip_reply(client_fd, SOCKS5_REP_GENERAL_FAILURE, ip, port);
            return -1;
        }
        printf("Connected to remote address %s:%d with FD %d\n",
               inet_ntoa(remote_addr.sin_addr), ntohs(port), remote_fd);

        send_ip_reply(client_fd, SOCKS5_REP_SUCCESS, ip, port);
    } else if (req.addr_type == SOCKS5_ATYP_DOMAIN_NAME) {
        // Get domain name
        char domain[UINT8_MAX + 1];
        int domain_len = recv_string(client_fd, domain);
        if (domain_len <= 0) {
            return -1;
        }
        // Get port
        in_port_t port;
        if (recv_exact(client_fd, &port, sizeof(in_port_t), 0) != 0) {
            return -1;
        }

        // Get ip by host name
        char port_s[8];
        sprintf(port_s, "%d", ntohs(port));
        struct addrinfo *addr_info;
        if (getaddrinfo(domain, port_s, NULL, &addr_info) != 0) {
            perror("getaddrinfo()");
            send_domain_reply(client_fd, SOCKS5_REP_GENERAL_FAILURE, domain, domain_len, port);
            return -1;
        }
        // Try connecting to host
        for (struct addrinfo *ai = addr_info; ai != NULL; ai = ai->ai_next) {
            int try_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (try_fd == -1) { continue; }
            if (connect(try_fd, ai->ai_addr, ai->ai_addrlen) == 0) {
                remote_fd = try_fd;
                break;
            } else {
                close(try_fd);
            }
        }
        freeaddrinfo(addr_info);

        if (remote_fd == -1) {
            fprintf(stderr, "Cannot connect to remote address %s:%d\n", domain, ntohs(port));
            send_domain_reply(client_fd, SOCKS5_REP_GENERAL_FAILURE, domain, domain_len, port);
            return -1;
        }
        printf("Connected to remote address %s:%d with FD %d\n", domain, ntohs(port), remote_fd);

        send_domain_reply(client_fd, SOCKS5_REP_SUCCESS, domain, domain_len, port);
    } else {
        fprintf(stderr, "Unsupported address type %#02x\n", req.addr_type);
        return -1;
    }
    return remote_fd;
}

void start_tunnel(int client_fd, int remote_fd) {
    printf("Running socks5 tunnel between FD %d and %d\n", client_fd, remote_fd);

    int maxfd = (client_fd > remote_fd) ? client_fd : remote_fd;
    uint8_t buffer[BUFSIZ];

    while (1) {
        fd_set rd_set;
        FD_ZERO(&rd_set);
        FD_SET(client_fd, &rd_set);
        FD_SET(remote_fd, &rd_set);

        if (select(maxfd + 1, &rd_set, NULL, NULL, NULL) < 0) {
            perror("select()");
            continue;
        }

        if (FD_ISSET(client_fd, &rd_set)) {
            ssize_t len = recv(client_fd, buffer, BUFSIZ, 0);
            if (len <= 0) { break; }
            send(remote_fd, buffer, len, 0);
        }

        if (FD_ISSET(remote_fd, &rd_set)) {
            ssize_t len = recv(remote_fd, buffer, BUFSIZ, 0);
            if (len <= 0) { break; }
            send(client_fd, buffer, len, 0);
        }
    }
}

void *client_worker(void *args) {
    int client_fd = (intptr_t) args;
    if (handle_greeting(client_fd) != 0) {
        close(client_fd);
        return NULL;
    }
    int remote_fd = handle_request(client_fd);
    if (remote_fd == -1) {
        close(client_fd);
        return NULL;
    }
    start_tunnel(client_fd, remote_fd);
    close(remote_fd);
    close(client_fd);
    return NULL;
}

_Noreturn void server_loop(int server_fd) {
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        // Check for incoming connections
        int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("accept()");
            continue;
        }
        // Disable Nagle algorithm to forward packets ASAP
        int optval = 1;
        if (setsockopt(client_fd, SOL_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
            perror("setsockopt()");
            close(client_fd);
            continue;
        }

        printf("Accepted connection from %s:%d with FD %d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);

        pthread_t client_tid;
        if (pthread_create(&client_tid, NULL, &client_worker, (void *) (intptr_t) client_fd) == 0) {
            pthread_detach(client_tid);
        } else {
            perror("pthread_create()");
            close(client_fd);
        }
    }
}

void print_help(const char *prog_name) {
    printf("USAGE: %s [-h] [-p PORT]\n", prog_name);
}

int main(int argc, char **argv) {
    int bind_port = 1080;

    int ch;
    while ((ch = getopt(argc, argv, "p:h")) != -1) {
        switch (ch) {
            case 'p':
                bind_port = atoi(optarg);
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Create a socket using TCP protocol over IPv4
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }
    // Reuse address
    int optval = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt()");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // Bind socket to given address
    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(bind_port);
    if (bind(server_fd, (struct sockaddr *) &bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind()");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // Listen to socket
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen()");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Server listening on %s:%d\n", inet_ntoa(bind_addr.sin_addr), bind_port);
    // Run server
    server_loop(server_fd);
    return 0;
}
