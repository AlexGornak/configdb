/*
 * cfg.h
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */

#ifndef CFG_H_
#define CFG_H_

#define VERSION         "1.7"

#define CFG_SIGN    (0xF7F57A5A)
#define CFG_VER     (1)

//architect specific definitions
#define MALLOC(size)            malloc(size)
#define FREE(ptr)               free(ptr)
typedef uint32_t pointer;
////////////////////////////////

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
    uint16_t snmpv2_enable;
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
//#define key_flash_key   7
//#define key_version     8
#define key_name        	1
#define key_net_cfg     	2
#define key_uart_cfg    	3
#define key_rs485gw_cfg 	4
#define key_eth_port_cfg	5
#define key_vlan_cfg		6
#define key_snmp_cfg    	7
#define key_rstp_cfg		8
#define key_ntp_cfg			9
#define key_ip_mon_cfg		10
#define key_pass			11
#define key_max_icmp_load	12
#define key_max_arp_load	13
#define key_users       14

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
#define key_protocol    	1
#define key_port       	2
#define key_timeout     	3
#define key_master_enable	4
#define key_breaker_boy    5
#define key_to_ip       	6
#define key_to_port     	7
//snmp_config childs
#define key_snmpv2c_enable	2
#define key_snmpv3_enable   3
#define key_community       4
#define key_snmpv3_users    5
//users array childs
#define key_username        1
#define key_sshpass         2
//snmp community childs
#define key_read            1
#define key_write           2
//snmp users array childs
#define key_snmp_username   1
#define key_auth_key        2
#define key_priv_key        3


enum {
    FT_NONE,
    FT_REC,
    FT_CHAR,
    FT_U8,
    FT_U16,
    FT_U32,
    FT_STR
};


typedef struct field_s field_t;

struct field_s {
    int key;
    int type;
    int N;
    field_t *next; //point to sibling
    char *name;
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
