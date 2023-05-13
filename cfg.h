/*
 * cfg.h
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */

#ifndef CFG_H_
#define CFG_H_

#define NUM_UARTS               2
#define COMMUNITY_NAME_SIZE     32
#define USER_NAME_SIZE          20

typedef struct {
    uint32_t baudrate;
    uint8_t stopbits;
    char parity;
    uint8_t master;
}uart_config_t;

typedef struct {
    uint8_t protocol;
    uint8_t pad;
    uint16_t port;
    uint8_t to_ip[4];
    uint16_t to_port;
} rs485gw_config_t;

typedef struct {
    uint8_t ip_addr[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t mac_addr[6];
} net_config_t;

struct snmp_community {
    char read[COMMUNITY_NAME_SIZE+1];
    char write[COMMUNITY_NAME_SIZE+1];
};
struct snmpv3_user {
    char username[USER_NAME_SIZE];
    uint8_t auth_key[20];
    uint8_t priv_key[20];
};

typedef struct{
    uint16_t snmpv3_enable; //v3 if 1 else v2c
    struct snmp_community community;
    struct snmpv3_user users[2];
}snmp_config_t;

typedef struct {
    char name[USER_NAME_SIZE];
    uint8_t sshpass[32];
} user_t;

typedef struct{
    uint32_t flash_key;
    uint16_t version;
    char rs485gw_name[USER_NAME_SIZE];
    net_config_t net_config;
    uart_config_t uart_config[NUM_UARTS];
    rs485gw_config_t rs485gw_config[NUM_UARTS];
    snmp_config_t snmp_config;
    user_t users[8];
} config_t;

enum {
    KEY_NONE,
    KEY_CONFIG,
    KEY_FLASH_KEY,
    KEY_VERSION,
    KEY_NAME,
    KEY_NET_CONFIG,
    KEY_IP_ADDR,
    KEY_NETMASK,
    KEY_GW_ADDR,
    KEY_MAC_ADDR,
    KEY_UART_CONFIG,
    KEY_BAUDRATE,
    KEY_STOPBITS,
    KEY_PARITY,
    KEY_MASTER,
    KEY_GW_CONFIG,
    KEY_PROTOCOL,
    KEY_PAD,
    KEY_PORT,
    KEY_TO_IP,
    KEY_TO_PORT,
    KEY_SNMP_CONFIG,
    KEY_SNMPV3_ENABLE,
    KEY_SNMP_COMMUNITY,
    KEY_READ,
    KEY_WRITE,
    KEY_SNMPV3_USER,
    KEY_AUTH_KEY,
    KEY_PRIV_KEY,
    KEY_USERS,
    KEY_SSHPASS
};

enum {
    FT_NONE,
    FT_REC,
    FT_ARRAY,
    FT_BYTES_ARRAY,
    FT_CHAR,
    FT_U8,
    FT_U16,
    FT_U32,
    FT_STR
};


typedef struct field_s field_t;
//typedef struct field_list field_list_t;

typedef struct field_list {
    struct field_list *next;
    field_t *field;
} field_list_t;

struct field_s {
    int key;
    int type;
    int sz;
    union {
        void *val;
        field_list_t *head;
    } data;
};

// export config to tree field_t
int cfg_export(config_t *cfg);
// import config from tree field_t
int cfg_import(config_t *cfg);
int cfg_read(void);
int cfg_write(void);

#endif /* CFG_H_ */
