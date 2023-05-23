/*
 * cfg.h
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */

#ifndef CFG_H_
#define CFG_H_

#define CFG_SIGN    (0xF7F57A5A)
#define CFG_VER     (1)

#define MALLOC(size)            malloc(size)
#define FREE(ptr)               free(ptr)


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

#define key_cfg         1
//config childs
#define key_flash_key   1
#define key_version     2
#define key_name        3
#define key_net_cfg     4
#define key_uart_cfg    5
#define key_rs485gw_cfg 6
#define key_snmp_cfg    7
#define key_users       8
//net_config childs
#define key_ip_addr     1
#define key_netmask     2
#define key_gateway     3
#define key_mac_addr    4
//uart_config childs
#define key_baudrate    1
#define key_stopbits    2
#define key_parity      3
#define key_master      4
//rs485gw_config childs
#define key_protocol    1
#define key_port        2
#define key_to_ip       3
#define key_to_port     4
//snmp_config childs
#define key_snmpv3_enable   1
#define key_community       2
#define key_snmpv3_users    3
//users array childs
#define key_username            1
#define key_sshpass         2
//snmp community childs
#define key_read            1
#define key_write           2
//snmp users array childs
#define key_snmp_username   1
#define key_auth_key        2
#define key_priv_key        3


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
    field_t *next; //point to sibling
    union {
        void *val;
        field_t *head; //point to list of childs
    };
};


typedef struct {
    uint32_t sign;
    uint16_t ver; 
    uint16_t size;
} cfg_hdr_t;
#define CFG_HDR_SIZE    sizeof(cfg_hdr_t)

// export config to tree field_t
int cfg_export(config_t *cfg);
// import config from tree field_t
int cfg_import(config_t *cfg);
int cfg_read(void);
int cfg_write(void);

#endif /* CFG_H_ */
