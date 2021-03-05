#pragma once

#include <stdint.h>

typedef struct {
    uint8_t version;
    uint8_t num_methods;
} socks5_client_hello_t;

typedef struct {
    uint8_t version;
    uint8_t method;
} socks5_server_hello_t;

typedef struct {
    uint8_t version;
    uint8_t command;
    uint8_t reserved;
    uint8_t addr_type;
} socks5_request_t;

typedef struct {
    uint8_t version;
    uint8_t reply;
    uint8_t reserved;
    uint8_t addr_type;
} socks5_reply_t;

// Version
#define SOCKS5_VERSION 0x05

// Authentication
#define SOCKS5_AUTH_NO_AUTH 0x00
#define SOCKS5_AUTH_NOT_ACCEPT 0xff

// Command
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_ASSOCIATE 0x03

// Address type
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN_NAME 0x03
#define SOCKS5_ATYP_IPV6 0x04

// Reply
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED 0x02
#define SOCKS5_REP_NET_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONNECTION_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDR_TYPE_NOT_SUPPORTED 0x08
