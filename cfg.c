/*
 * cfg.c
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */
#define VERSION         "1.4"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include "cfg.h"

#if 0
#include "debug.h"
#define PRINTF(...)     printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

typedef uint64_t pointer;

enum {
    ERR_NONE,
    ERR_MEM,
    ERR_PARAM
};

#define FLASH_KEY           0xf357f245
#define VERSION_MAJOR       1
#define VERSION_MINOR       40
enum  {
    GW_PROTOCOL_NONE,
    GW_PROTOCOL_UDP,
    GW_PROTOCOL_TCP,
    GW_PROTOCOL_UDP_TRANSPARENT,
    GW_PROTOCOL_TCP_TRANSPARENT,
    GW_PROTOCOL_CONTROLLER,
    GW_PROTOCOL_UDP_BYBYTE
};
config_t cfg = { .flash_key = FLASH_KEY ,\
        .version = (VERSION_MAJOR<<8) | (VERSION_MINOR & 0xFF), .rs485gw_name = "RS485GW",\
        .net_config = {.ip_addr={172, 23, 11, 105}, .gateway={172, 23, 11, 1}, .netmask={255, 255, 255, 0}, .mac_addr={0x00, 0x50, 0xC2, 0x7D, 0x66, 0xA5}},\
        .uart_config = {{.baudrate = 38400, .stopbits = 1, .parity = 'N', .master=0},\
                        {.baudrate = 38400, .stopbits = 1, .parity = 'N', .master=0}},\
        .rs485gw_config = {{.protocol=GW_PROTOCOL_NONE, .port=4001, .to_ip={0,0,0,0}, .to_port=0},\
                           {.protocol=GW_PROTOCOL_NONE, .port=4002, .to_ip={0,0,0,0}, .to_port=0}},\
        .snmp_config = {//.engineid = "12345", .engineid_len = 5,
                        .snmpv3_enable = 1,
                        .community={.read="public", .write="private"},
                        .users={{.username = "admin",
                                 .auth_key="\xa8\xd2\x48\x1f\x63\xde\xbc\x41\xdf\x37\x0f\xe2\x20\x2a\xc0\xdf\xb8\xc2\x42\x52",
                                 .priv_key="\xa8\xd2\x48\x1f\x63\xde\xbc\x41\xdf\x37\x0f\xe2\x20\x2a\xc0\xdf\xb8\xc2\x42\x52"
                                },
                                {.username = "user",
                                 .auth_key="\xa8\xd2\x48\x1f\x63\xde\xbc\x41\xdf\x37\x0f\xe2\x20\x2a\xc0\xdf\xb8\xc2\x42\x52",
                                 .priv_key="\xa8\xd2\x48\x1f\x63\xde\xbc\x41\xdf\x37\x0f\xe2\x20\x2a\xc0\xdf\xb8\xc2\x42\x52"
                                }
                               }
                        },
        .users = {{.name="admin\0", .sshpass="\x76\x42\x4c\x8a\xf8\x78\xad\x0d\xc0\xc9\x47\x8b\x5d\xe5\x5a\x2e\xa4\x2c\x9e\x69\x04\x32\xf9\x90\xd3\x9b\x65\x9e\x9f\xb8\xde\x1e"}, //spbec
                  {.name="user\0",  .sshpass="\x76\x42\x4c\x8a\xf8\x78\xad\x0d\xc0\xc9\x47\x8b\x5d\xe5\x5a\x2e\xa4\x2c\x9e\x69\x04\x32\xf9\x90\xd3\x9b\x65\x9e\x9f\xb8\xde\x1e"}, //spbec
                  {.name="\0"}}
};

config_t cfg1;

static void *alloc_mem(int size);
static field_t *new_field(int key, int type, void *val);
static field_t *new_bytes_array(int key, int sz, uint8_t *val);
static int add_field(field_t *parent, field_t *child);
static void print_field(field_t *f, int level);
static void prepare_to_write(field_t *f);
static void prepare_after_read(field_t *f);

static void print_bytes_array(int n, uint8_t *a);

#define MEMB_SIZE   4096
cfg_hdr_t *cfg_hdr_ptr;
uint8_t *memb;
//uint8_t memb[MEMB_SIZE];
uint32_t ptr = 0;
field_t *root;

int main(int argc, char **argv)
{
    memb = MALLOC(MEMB_SIZE);
    cfg_hdr_ptr = (cfg_hdr_t *)memb;
    cfg_hdr_ptr->sign = CFG_SIGN;
    cfg_hdr_ptr->ver = CFG_VER;
    memb += CFG_HDR_SIZE;
    
    cfg_export(&cfg);
    print_field(root, 0);
    printf("ptr=%d\n", ptr); 
    cfg_hdr_ptr->size = ptr;  
    cfg_write();
    
    cfg_read();
    printf("readed=%d bytes\n", ptr); 
    printf("sign = %08X, ver = %d, size = %d\n", \
    cfg_hdr_ptr->sign, cfg_hdr_ptr->ver, cfg_hdr_ptr->size);
    
    print_field(root, 0);
    printf("************************\n\n");
    cfg_import(&cfg1);
    printf("flash_key = %u\n", cfg1.flash_key);
    printf("version = %d\n", cfg1.version);
    printf("name = %s\n", cfg1.rs485gw_name);

    printf("ip_addr = %d.%d.%d.%d\n", cfg1.net_config.ip_addr[0], cfg1.net_config.ip_addr[1],\
     cfg1.net_config.ip_addr[2], cfg1.net_config.ip_addr[3]);
    printf("netmask = %d.%d.%d.%d\n", cfg1.net_config.netmask[0], cfg1.net_config.netmask[1],\
     cfg1.net_config.netmask[2], cfg1.net_config.netmask[3]);
    printf("gateway = %d.%d.%d.%d\n", cfg1.net_config.gateway[0], cfg1.net_config.gateway[1],\
     cfg1.net_config.gateway[2], cfg1.net_config.gateway[3]);
    printf("mac_addr = %02x:%02x:%02x:%02x:%02x:%02x\n", cfg1.net_config.mac_addr[0], cfg1.net_config.mac_addr[1],\
     cfg1.net_config.mac_addr[2], cfg1.net_config.mac_addr[3], cfg1.net_config.mac_addr[4], cfg1.net_config.mac_addr[5]);

    for (int i=0; i<NUM_UARTS; i++) {
        printf("uart_%d: br=%u parity=%c stopbits=%d master=%d\n", i, cfg1.uart_config[i].baudrate, \
        cfg1.uart_config[i].parity, cfg1.uart_config[i].stopbits, cfg1.uart_config[i].master);
    }

    for (int i=0; i<NUM_UARTS; i++) {
        printf("rs485gw_%d: protocol=%d port=%d to_ip=%d.%d.%d.%d to_port=%d\n", i, cfg1.rs485gw_config[i].protocol, \
        cfg1.rs485gw_config[i].port, cfg1.rs485gw_config[i].to_ip[0], cfg1.rs485gw_config[i].to_ip[1], \
        cfg1.rs485gw_config[i].to_ip[2], cfg1.rs485gw_config[i].to_ip[3], cfg1.rs485gw_config[i].to_port);
    }
    
    printf("snmpv3_enable=%d\n", cfg1.snmp_config.snmpv3_enable);
    printf("community_read=%s\n", cfg1.snmp_config.community.read);
    printf("community_write=%s\n", cfg1.snmp_config.community.write);
    printf("snmpv3_users:\n");
    for (int i=0; i<2; i++) {
        printf("snmpv3_user_%d:\n", i);
        printf("\tname=%s\n", cfg1.snmp_config.users[i].username);
        printf("\tauth_key=["); print_bytes_array(20, cfg1.snmp_config.users[i].auth_key); printf("]\n");
        printf("\tpriv_key=["); print_bytes_array(20, cfg1.snmp_config.users[i].priv_key); printf("]\n");
    }
    for (int i=0; i<8; i++) {
        if (*cfg1.users[i].name == 0) break;
        printf("user_%d\n", i);
        printf("\tname=%s\n", cfg1.users[i].name);
        printf("\tsshpass=["); print_bytes_array(32, cfg1.users[i].sshpass); printf("]\n");
    }
    return 0;
}

static void *alloc_mem(int size)
{
    void *p;
    p = memb + ptr;
    if (size % 4) size = (size/4 + 1)*4;
    if (ptr + size > MEMB_SIZE)
        return NULL;
    ptr += size;
    return p;
}

static field_t *new_field(int key, int type, void *val)
{
    field_t *fptr = alloc_mem(sizeof(field_t));
    if (!fptr) {
        return NULL;
    }
    fptr->key = key;
    fptr->type = type;
    if (val) fptr->val = val;
    else fptr->head = NULL;
    return fptr;
}

static field_t *new_bytes_array(int key, int sz, uint8_t *val)
{
    field_t *fptr = alloc_mem(sizeof(field_t));
    if (!fptr) {
        return NULL;
    }
    fptr->key = key;
    fptr->type = FT_BYTES_ARRAY;
    fptr->sz = sz;
    fptr->val = val;
    return fptr;
}

static int add_field(field_t *parent, field_t *child)
{
    if (!parent) return ERR_PARAM;
    if (!child) return ERR_NONE;
    child->next = parent->head;
    parent->head = child;
    return ERR_NONE;
} 

static field_t *get_field_from(field_t *f, int n, int *path)
{
    int *p = path;
    field_t *l;
    if (n == 0) return f;
    if (f->key == *p) {
        p++; n--;
        if (n == 0) return f;
        for (l=f->head; l; l=l->next) {
            field_t *fld = get_field_from(l, n, p);
            if (fld) return fld;
        }
    }
    return NULL;
}

static field_t *get_field(int n, int *path)
{
    return get_field_from(root, n, path);
}

static void print_bytes_array(int n, uint8_t *a)
{
    for (int i=0; i<n; i++)
        printf(" %d", a[i]);    
}

static void print_field(field_t *f, int level)
{
    int i;
    for (i=0; i<level; i++) printf("    ");
    printf("key=%d, type=%d\n", f->key, f->type);
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            for (field_t *l = f->head; l; l=l->next) {
                print_field(l, level+1);
            }
            break;
        case FT_BYTES_ARRAY:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=[");
            print_bytes_array(f->sz, (uint8_t *)f->val);
            //for (i=0; i<f->sz; i++)
                //printf(" %d", ((uint8_t *)f->val)[i]);
            printf("]\n");
            break;
        case FT_CHAR:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val='%c'\n", *(char *)f->val);
            break;
        case FT_STR:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%s\n", (char *)f->val);
            break;
        case FT_U8:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%d\n", *(uint8_t *)f->val);
            break;
        case FT_U16:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%d\n", *(uint16_t *)f->val);
            break;
        case FT_U32:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%u\n", *(uint32_t *)f->val);
            break;
        default:
            break;
    }
}

static void prepare_to_write(field_t *f)
{
    field_t *tmp, *chld;
    tmp = f->next;
    if (tmp)
        f->next = (field_t *)((pointer)tmp - (pointer)memb);
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            chld = f->head;
            if (chld)
                f->head = (field_t *)((pointer)chld - (pointer)memb);
            while (chld) {
                tmp = chld->next;
                prepare_to_write(chld);
                //if (tmp)
                    //chld->next = (field_t *)((pointer)tmp - (pointer)memb);
                chld = tmp;
            }
            break;
        case FT_BYTES_ARRAY:
        case FT_CHAR:
        case FT_STR:
        case FT_U8:
        case FT_U16:
        case FT_U32:
            if (f->val)
                f->val = (void *)((pointer)f->val - (pointer)memb);
            break;
        default:
            break;
    }
    
}

static void prepare_after_read(field_t *f)
{
    field_t *chld;
    if (f->next)
        f->next = (field_t *)((pointer)f->next + (pointer)memb);
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            if (f->head)
                f->head = (field_t *)((pointer)f->head + (pointer)memb);
            chld = f->head;
            while (chld) {
                prepare_after_read(chld);
                chld = chld->next;
            }
            break;
        case FT_BYTES_ARRAY:
        case FT_CHAR:
        case FT_STR:
        case FT_U8:
        case FT_U16:
        case FT_U32:
            if (f->val)
                f->val = (void *)((pointer)f->val + (pointer)memb);
            break;
        default:
            break;
    }
}

int cfg_export(config_t *cfg)
{
    int i;
    void *val;
    field_t *fld, *fld1, *fld2;

    root = new_field(KEY_CONFIG, FT_REC, NULL);
    
    /********** uint32_t flash_key **************/
    val = alloc_mem(sizeof(uint32_t));
    *(uint32_t *)val = cfg->flash_key;
    fld = new_field(KEY_FLASH_KEY, FT_U32, val);
    add_field(root, fld);
    /********************************************/
    
    /********** uint16_t version ****************/
    val = alloc_mem(sizeof(uint16_t));
    *(uint16_t *)val = cfg->version;
    fld = new_field(KEY_VERSION, FT_U16, val);
    add_field(root, fld);
    /********************************************/
    
    /*****char rs485gw_name[USER_NAME_SIZE]******/
    val = alloc_mem(USER_NAME_SIZE);
    memcpy(val, cfg->rs485gw_name, USER_NAME_SIZE);
    fld = new_field(KEY_NAME, FT_STR, val);
    add_field(root, fld);
    /********************************************/
    
    /************** net_config ******************/
    fld = new_field(KEY_NET_CONFIG, FT_REC, NULL);
    
    val = alloc_mem(4);
    memcpy(val, cfg->net_config.ip_addr, 4);
    fld1 = new_bytes_array(KEY_IP_ADDR, 4, val);
    add_field(fld, fld1);
    
    val = alloc_mem(4);
    memcpy(val, cfg->net_config.netmask, 4);
    fld1 = new_bytes_array(KEY_NETMASK, 4, val);
    add_field(fld, fld1);

    val = alloc_mem(4);
    memcpy(val, cfg->net_config.gateway, 4);
    fld1 = new_bytes_array(KEY_GW_ADDR, 4, val);
    add_field(fld, fld1);

    val = alloc_mem(6);
    memcpy(val, cfg->net_config.mac_addr, 6);
    fld1 = new_bytes_array(KEY_MAC_ADDR, 6, val);
    add_field(fld, fld1);
    add_field(root, fld);
    /********************************************/
    
    /********* uart_config[NUM_UARTS] ***********/
    fld = new_field(KEY_UART_CONFIG, FT_ARRAY, NULL);
    for (i=0; i<NUM_UARTS; i++) {
        field_t *f, *f1;
        f = new_field(i, FT_REC, NULL);
         val = alloc_mem(sizeof(uint32_t));
        *(uint32_t *)val = cfg->uart_config[i].baudrate;
        f1 = new_field(KEY_BAUDRATE, FT_U32, val);
        add_field(f, f1);
         val = alloc_mem(sizeof(uint8_t));
        *(uint8_t *)val = cfg->uart_config[i].stopbits;
        f1 = new_field(KEY_STOPBITS, FT_U8, val);
        add_field(f, f1);
         val = alloc_mem(sizeof(char));
        *(char*)val = cfg->uart_config[i].parity;
        f1 = new_field(KEY_PARITY, FT_CHAR, val);
        add_field(f, f1);
         val = alloc_mem(sizeof(uint8_t));
        *(uint8_t *)val = cfg->uart_config[i].master;
        f1 = new_field(KEY_MASTER, FT_U8, val);
        add_field(f, f1);
        add_field(fld, f);
    }
    add_field(root, fld);
    /********************************************/
    
    /******** rs485gw_config[NUM_UARTS] *********/
    fld = new_field(KEY_GW_CONFIG, FT_ARRAY, NULL);
    for (i=0; i<NUM_UARTS; i++) {
        field_t *f, *f1;
        f = new_field(i, FT_REC, NULL);
        
        val = alloc_mem(sizeof(uint8_t));
        *(uint8_t *)val = cfg->rs485gw_config[i].protocol;
        f1 = new_field(KEY_PROTOCOL, FT_U8, val);
        add_field(f, f1);

        val = alloc_mem(sizeof(uint8_t));
        *(uint8_t *)val = cfg->rs485gw_config[i].pad;
        f1 = new_field(KEY_PAD, FT_U8, val);
        add_field(f, f1);
        
        val = alloc_mem(sizeof(uint16_t));
        *(uint16_t *)val = cfg->rs485gw_config[i].port;
        f1 = new_field(KEY_PORT, FT_U16, val);
        add_field(f, f1);

        val = alloc_mem(4);
        memcpy(val, cfg->rs485gw_config[i].to_ip, 4);
        f1 = new_bytes_array(KEY_TO_IP, 4, val);
        add_field(f, f1);

        val = alloc_mem(sizeof(uint16_t));
        *(uint16_t *)val = cfg->rs485gw_config[i].to_port;
        f1 = new_field(KEY_TO_PORT, FT_U16, val);
        add_field(f, f1);
        
        add_field(fld, f);
    }
    add_field(root, fld);
    /********************************************/
    
    /************ snmp_config *******************/
    fld = new_field(KEY_SNMP_CONFIG, FT_REC, NULL);
   
    val = alloc_mem(sizeof(uint16_t));
    *(uint16_t *)val = cfg->snmp_config.snmpv3_enable;
    fld1 = new_field(KEY_SNMPV3_ENABLE, FT_U16, val);
    add_field(fld, fld1);

    fld1 = new_field(KEY_SNMP_COMMUNITY, FT_REC, NULL);
    val = alloc_mem(COMMUNITY_NAME_SIZE+1);
    memcpy(val, cfg->snmp_config.community.read, COMMUNITY_NAME_SIZE+1);
    fld2 = new_field(KEY_READ, FT_STR, val);
    add_field(fld1, fld2);
    val = alloc_mem(COMMUNITY_NAME_SIZE+1);
    memcpy(val, cfg->snmp_config.community.write, COMMUNITY_NAME_SIZE+1);
    fld2 = new_field(KEY_WRITE, FT_STR, val);
    add_field(fld1, fld2);
    add_field(fld, fld1);

    fld1 = new_field(KEY_SNMPV3_USER, FT_ARRAY, NULL);
    for (i=0; i<2; i++) {
        field_t *f, *f1;
        f = new_field(i, FT_REC, NULL);
        
        val = alloc_mem(USER_NAME_SIZE);
        memcpy(val, cfg->snmp_config.users[i].username, USER_NAME_SIZE);
        f1 = new_field(KEY_NAME, FT_STR, val);
        add_field(f, f1);
        val = alloc_mem(20);
        memcpy(val, cfg->snmp_config.users[i].auth_key, 20);
        f1 = new_bytes_array(KEY_AUTH_KEY, 20, val);
        add_field(f, f1);
        val = alloc_mem(20);
        memcpy(val, cfg->snmp_config.users[i].priv_key, 20);
        f1 = new_bytes_array(KEY_PRIV_KEY, 20, val);
        add_field(f, f1);
        
        add_field(fld1, f);
    }    
    add_field(fld, fld1);
  
    add_field(root, fld);
    /********************************************/

    /************** users[8] ********************/
    fld = new_field(KEY_USERS, FT_ARRAY, NULL);
    for (i=0; i<8; i++) {
        field_t *f, *f1;
        f = new_field(i, FT_REC, NULL);
        
        val = alloc_mem(USER_NAME_SIZE);
        memcpy(val, cfg->users[i].name, USER_NAME_SIZE);
        f1 = new_field(KEY_NAME, FT_STR, val);
        add_field(f, f1);
        val = alloc_mem(32);
        memcpy(val, cfg->users[i].sshpass, 32);
        f1 = new_bytes_array(KEY_SSHPASS, 32, val);
        add_field(f, f1);
        add_field(fld, f);
        if (*cfg->users[i].name == 0) break;
    }        
    add_field(root, fld);
    /********************************************/
    
    return ERR_NONE;
}

int cfg_import(config_t *cfg)
{
    field_t *f, *f1;
    
    int p[] = {KEY_CONFIG, KEY_FLASH_KEY, 0, 0};
    f = get_field(2, p);
    if (f) cfg->flash_key = *(uint32_t *)f->val;
    
    p[1] = KEY_VERSION;
    f = get_field(2, p);
    if (f) cfg->version = *(uint16_t *)f->val;
    
    p[1] = KEY_NAME;
    f = get_field(2, p);
    if (f) strcpy(cfg->rs485gw_name, (char *)f->val);
    
    p[1] = KEY_UART_CONFIG;
    f = get_field(2, p);
    if (f) {
        int p1[3] = {KEY_UART_CONFIG, 0, 0};
        for (int i=0; i<NUM_UARTS; i++) {
            p1[1] = i;
            p1[2] = KEY_BAUDRATE;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].baudrate = *(uint32_t *)f1->val;
            p1[2] = KEY_STOPBITS;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].stopbits = *(uint8_t *)f1->val;
            p1[2] = KEY_PARITY;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].parity = *(char *)f1->val;
            p1[2] = KEY_MASTER;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].master = *(uint8_t *)f1->val;
        }
    }
    
    p[1] = KEY_NET_CONFIG;
    p[2] = KEY_IP_ADDR;
    f = get_field(3, p);
    if (f) memcpy(cfg->net_config.ip_addr, (uint8_t *)f->val, f->sz);
    p[2] = KEY_NETMASK;
    f = get_field(3, p);
    if (f) memcpy(cfg->net_config.netmask, (uint8_t *)f->val, f->sz);
    p[2] = KEY_GW_ADDR;
    f = get_field(3, p);
    if (f) memcpy(cfg->net_config.gateway, (uint8_t *)f->val, f->sz);
    p[2] = KEY_MAC_ADDR;
    f = get_field(3, p);
    if (f) memcpy(cfg->net_config.mac_addr, (uint8_t *)f->val, f->sz);
    
    p[1] = KEY_GW_CONFIG;
    f = get_field(2, p);
    if (f) {
        int p1[3] = {KEY_GW_CONFIG, 0, 0};
        for (int i=0; i<NUM_UARTS; i++) {
            p1[1] = i;
            p1[2] = KEY_PROTOCOL;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->rs485gw_config[i].protocol = *(uint8_t *)f1->val;
            p1[2] = KEY_PORT;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->rs485gw_config[i].port = *(uint16_t *)f1->val;
            p1[2] = KEY_TO_PORT;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->rs485gw_config[i].to_port = *(uint16_t *)f1->val;
            p1[2] = KEY_TO_IP;
            f1 = get_field_from(f, 3, p1);
            if (f1) memcpy(cfg->rs485gw_config[i].to_ip, (uint16_t *)f1->val, f1->sz);
        }        
    }

    p[1] = KEY_SNMP_CONFIG;
    
    p[2] = KEY_SNMPV3_ENABLE;
    f = get_field(3, p);
    if (f) cfg->snmp_config.snmpv3_enable = *(uint8_t *)f->val;
    
    p[2] = KEY_SNMP_COMMUNITY;
    p[3] = KEY_READ;
    f = get_field(4, p);
    if (f) strcpy(cfg->snmp_config.community.read, (char *)f->val);
    p[3] = KEY_WRITE;
    f = get_field(4, p);
    if (f) strcpy(cfg->snmp_config.community.write, (char *)f->val);

    p[2] = KEY_SNMPV3_USER;
    f = get_field(3, p);
    if (f) {
        int p1[3] = {KEY_SNMPV3_USER, 0, 0};
        for (int i=0; i<2; i++) {
            p1[1] = i;
            p1[2] = KEY_NAME;
            f1 = get_field_from(f, 3, p1);
            if (f1) stpcpy(cfg->snmp_config.users[i].username, (char *)f1->val);
            p1[2] = KEY_AUTH_KEY;
            f1 = get_field_from(f, 3, p1);
            if (f1) memcpy(cfg->snmp_config.users[i].auth_key, (char *)f1->val, f1->sz);
            p1[2] = KEY_PRIV_KEY;
            f1 = get_field_from(f, 3, p1);
            if (f1) memcpy(cfg->snmp_config.users[i].priv_key, (char *)f1->val, f1->sz);
        }
    }
    
    p[1] = KEY_USERS;
    f = get_field(2, p);
    if (f) {
        int p1[3] = {KEY_USERS, 0, 0};
        for (int i=0; i<8; i++) {
            p1[1] = i;
            p1[2] = KEY_NAME;
            f1 = get_field_from(f, 3, p1);
            if (f1) {
                strcpy(cfg->users[i].name, (char *)f1->val);
                if (*(char *)f1->val == 0) break;
            }
            p1[2] = KEY_SSHPASS;
            f1 = get_field_from(f, 3, p1);
            if (f1) memcpy(cfg->users[i].sshpass, (uint8_t *)f1->val, f1->sz);
        }
    }    
    return ERR_NONE;
}

int cfg_write(void)
{
    FILE *fd;     
    prepare_to_write(root);
    fd = fopen("config.cfg", "wb"); 
    fwrite(cfg_hdr_ptr, sizeof(uint8_t), ptr+CFG_HDR_SIZE, fd);
    fclose(fd);
    return ERR_NONE;
}

int cfg_read(void)
{
    FILE *fd;     
    fd = fopen("config.cfg", "rb"); 
    if (fd) {
        ptr = fread(cfg_hdr_ptr, sizeof(uint8_t), MEMB_SIZE, fd);
        fclose(fd);
    }
    root = (field_t *)memb;
    
    prepare_after_read(root);
    return ERR_NONE;

}
