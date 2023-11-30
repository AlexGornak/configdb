/*
 * cfg.c
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */
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
static field_t *new_field(int key, int type, int N, const char* name, void *val);
static int add_field(field_t *parent, field_t *child);
static void print_field(field_t *f, int level);
static void prepare_to_write(field_t *f);
static void prepare_after_read(field_t *f);

static void print_array(int type, int n, void *a);

#define MEMB_SIZE  9000 
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
 /*   
    cfg_export(&cfg);

    print_field(root, 0);
    printf("ptr=%d\n", ptr); 
    cfg_hdr_ptr->size = ptr;  
    cfg_write();
  */  
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
        printf("\tauth_key=["); print_array(FT_U8, 20, cfg1.snmp_config.users[i].auth_key); printf("]\n");
        printf("\tpriv_key=["); print_array(FT_U8, 20, cfg1.snmp_config.users[i].priv_key); printf("]\n");
    }
    for (int i=0; i<8; i++) {
        if (*cfg1.users[i].name == 0) break;
        printf("user_%d\n", i);
        printf("\tname=%s\n", cfg1.users[i].name);
        printf("\tsshpass=["); print_array(FT_U8, 32, cfg1.users[i].sshpass); printf("]\n");
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

static int get_type_size(int type)
{
    int sz = 0;
    switch (type) {
        //case FT_ARRAY_U8:
        case FT_CHAR:
        case FT_STR:
        case FT_U8:
            sz = sizeof(char);
            break;        
        case FT_U16:
            sz = sizeof(uint16_t);
            break;
        case FT_U32:
            sz = sizeof(uint32_t);
            break;
        default:
            break;
    }
    return sz;
}
static field_t *new_field(int key, int type, int N, const char* name, void *val)
{
    field_t *fptr = alloc_mem(sizeof(field_t));
    if (!fptr) {
        return NULL;
    }
    char* fname = NULL;
    if (name) fname = alloc_mem(strlen(name)+1);
    if (fname) strcpy(fname, name);
    fptr->key = key;
    fptr->type = type;
    fptr->name = fname;
    fptr->N = N;
    if (val) {
        int sz;
        sz = get_type_size(type)*N;
        void *fval = alloc_mem(sz);
        if (fval) {
            memcpy(fval, val, sz);
        }
        fptr->val = fval;
    }
    else fptr->head = NULL;
    return fptr;
}

#define new_rec(key, name)                  new_field(key, FT_REC, 1, name, NULL)
#define new_val(key, type, name, val)       new_field(key, type, 1, name, val)
#define new_str(key, N, name, val)          new_field(key, FT_STR, N, name, val)
#define new_array(key, type, N, name, val)  new_field(key, type, N, name, val)

static int add_field(field_t *parent, field_t *child)
{
    if (!parent) return ERR_PARAM;
    if (!child) return ERR_NONE;
    child->next = parent->head;
    parent->head = child;
    return ERR_NONE;
} 


static field_t *get_field(field_t *from, int n, int *path)
{
    int *p = path;
    field_t *l;
    if (n==0) return from;
    for (l=from->head; l; l=l->next) {
        if (l->key==*p) {
            p++;
            field_t *fld=get_field(l, n-1, p);
            if (fld) return fld;
        }
    }
    return NULL;
}

static void get_val(field_t *from, int n, int *path, void* val)
{
    field_t *f = get_field(from, n, path);
    if (f) {
        int sz;
        sz = get_type_size(f->type)*f->N;
        if (f->val && sz && val) {
            memcpy(val, f->val, sz);
        }
    }
}

static void print_array(int type, int n, void *a)
{
    for (int i=0; i<n; i++) {
        if (type==FT_CHAR) printf(" %x", ((uint8_t *)a)[i]);
        else if (type==FT_U8) printf(" %u", ((uint8_t *)a)[i]); 
        else if (type==FT_U16) printf(" %u", ((uint16_t *)a)[i]); 
        else if (type==FT_U32) printf(" %u", ((uint32_t *)a)[i]); 
    }
}

static void print_field(field_t *f, int level)
{
    int i;
    for (i=0; i<level; i++) printf("    ");
    printf("key=%d, type=%d", f->key, f->type);
    if (f->type == FT_REC) {
        if (f->name) printf(", fname=%s\n", f->name);
        else printf("\n");
        for (field_t *l = f->head; l; l=l->next) {
            print_field(l, level+1);
        }
    } else {
        printf("\n");
        for (i=0; i<level+1; i++) printf("    ");
        if (f->type != FT_STR && f->N > 1) { //array
            printf("%s=[", f->name?f->name:"val");
            print_array(f->type, f->N, f->val);
            printf("]\n");
        } else {
            printf("%s=", f->name?f->name:"val");
            if (f->type == FT_CHAR) printf("'%c'\n", *(char *)f->val);
            else if (f->type == FT_STR) printf("%s\n", (char *)f->val);
            else if (f->type == FT_U8) printf("%d\n", *(uint8_t *)f->val);
            else if (f->type == FT_U16) printf("%d\n", *(uint16_t *)f->val);
            else if (f->type == FT_U32) printf("%u\n", *(uint32_t *)f->val);
        }
    }
}

static void prepare_to_write(field_t *f)
{
    field_t *tmp, *chld;
    tmp = f->next;
    if (tmp)
        f->next = (field_t *)((pointer)tmp - (pointer)memb);
    if (f->name)
        f->name = (char *)((pointer)f->name - (pointer)memb);
    switch (f->type) {
        case FT_REC:
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
    if (f->name)
        f->name = (char *)((pointer)f->name + (pointer)memb);
    switch (f->type) {
        case FT_REC:
            if (f->head)
                f->head = (field_t *)((pointer)f->head + (pointer)memb);
            chld = f->head;
            while (chld) {
                prepare_after_read(chld);
                chld = chld->next;
            }
            break;
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
    field_t *fld, *fld1, *fld2;

    root = new_rec(key_cfg, "config");

    /********** uint32_t flash_key **************/
    //fld = new_val(KEY_FLASH_KEY, FT_U32, "flash_key", &cfg->flash_key);
    //add_field(root, fld);
    /********************************************/

    /********** uint16_t version ****************/
    //fld = new_val(KEY_VERSION, FT_U16, "version", &cfg->version);
    //add_field(root, fld);
    /********************************************/

    /*****char rs485gw_name[USER_NAME_SIZE]******/
    fld = new_str(key_name, USER_NAME_SIZE, "rs485gw_name", &cfg->rs485gw_name);
    add_field(root, fld);
    /********************************************/

    /************** net_config ******************/
    fld = new_rec(key_net_cfg, "net_config");
    
    fld1 = new_array(key_ip_addr, FT_U8, 4, "ip_addr", cfg->net_config.ip_addr);
    add_field(fld, fld1);    
    fld1 = new_array(key_netmask, FT_U8, 4, "netmask", cfg->net_config.netmask);
    add_field(fld, fld1);
    fld1 = new_array(key_gateway, FT_U8, 4, "gateway", cfg->net_config.gateway);
    add_field(fld, fld1);
    fld1 = new_array(key_mac_addr, FT_U8, 6, "mac", cfg->net_config.mac_addr);
    add_field(fld, fld1);
    
    add_field(root, fld);
    /********************************************/

    /********* uart_config[NUM_UARTS] ***********/
    fld = new_rec(key_uart_cfg, "uart_config");
    for (i=0; i<NUM_UARTS; i++) {
        field_t *f, *f1;
        f = new_rec(i, NULL);
        
        f1 = new_val(key_baudrate, FT_U32, "baudrate", &cfg->uart_config[i].baudrate);
        add_field(f, f1);
        f1 = new_val(key_stopbits, FT_U8, "stopbits", &cfg->uart_config[i].stopbits);
        add_field(f, f1);
        f1 = new_val(key_parity, FT_CHAR, "parity", &cfg->uart_config[i].parity);
        add_field(f, f1);
        f1 = new_val(key_master, FT_U8, "master", &cfg->uart_config[i].master);
        add_field(f, f1);
        
        add_field(fld, f);
    }
    add_field(root, fld);
    /********************************************/

    /******** rs485gw_config[NUM_UARTS] *********/
    fld = new_rec(key_rs485gw_cfg, "rs485gw_config");
    for (i=0; i<NUM_UARTS; i++) {
        field_t *f, *f1;
        f = new_rec(i, NULL);
        
        f1 = new_val(key_protocol, FT_U8, "protocol", &cfg->rs485gw_config[i].protocol);
        add_field(f, f1);
        //f1 = new_field(KEY_PAD, FT_U8, &cfg->rs485gw_config[i].pad);
        //add_field(f, f1);
        f1 = new_val(key_port, FT_U16, "port", &cfg->rs485gw_config[i].port);
        add_field(f, f1);
        f1 = new_array(key_to_ip, FT_U8, 4, "to_ip", cfg->rs485gw_config[i].to_ip);
        add_field(f, f1);
        f1 = new_val(key_to_port, FT_U16, "to_port", &cfg->rs485gw_config[i].to_port);
        add_field(f, f1);
        
        add_field(fld, f);
    }
    add_field(root, fld);
    /********************************************/

    /************ snmp_config *******************/
    fld = new_rec(key_snmp_cfg, "snmp_config");
   
    fld1 = new_val(key_snmpv3_enable, FT_U16, "snmpv3_enable", &cfg->snmp_config.snmpv3_enable);
    add_field(fld, fld1);

    fld1 = new_rec(key_community, "community");
    fld2 = new_str(key_read, COMMUNITY_NAME_SIZE+1, "public", cfg->snmp_config.community.read);
    add_field(fld1, fld2);
    fld2 = new_str(key_write, COMMUNITY_NAME_SIZE+1, "private", cfg->snmp_config.community.write);
    add_field(fld1, fld2);
    add_field(fld, fld1);

    fld1 = new_rec(key_snmpv3_users, "snmpv3_users");
    for (i=0; i<2; i++) {
        field_t *f, *f1;
        f = new_rec(i, NULL);
        
        f1 = new_str(key_snmp_username, USER_NAME_SIZE, "name", cfg->snmp_config.users[i].username);
        add_field(f, f1);
        f1 = new_array(key_auth_key, FT_CHAR, 20, "auth_key", cfg->snmp_config.users[i].auth_key);
        add_field(f, f1);
        f1 = new_array(key_priv_key, FT_CHAR, 20, "priv_key", cfg->snmp_config.users[i].priv_key);
        add_field(f, f1);
        
        add_field(fld1, f);
    }    
    add_field(fld, fld1);
  
    add_field(root, fld);
    /********************************************/

    /************** users[8] ********************/
    fld = new_rec(key_users, "ssh_users");
    for (i=0; i<8; i++) {
        field_t *f, *f1;
        f = new_rec(i, NULL);
        
        f1 = new_str(key_username, USER_NAME_SIZE, "name", cfg->users[i].name);
        add_field(f, f1);
        f1 = new_array(key_sshpass, FT_CHAR, 32, "ssh_pass", cfg->users[i].sshpass);
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
    field_t *f;
    
    int p[] = {0, 0, 0};
    int p1[2] = {0, 0};
    
    //get_val(root, 1, p, &cfg->flash_key);
    
    //p[0] = KEY_VERSION;
    //get_val(root, 1, p, &cfg->version);
    
    p[0] = key_name;
    get_val(root, 1, p, &cfg->rs485gw_name);
    
    p[0] = key_uart_cfg;
    f = get_field(root, 1, p);
    if (f) {
        for (int i=0; i<NUM_UARTS; i++) {
            p1[0] = i;
            p1[1] = key_baudrate;
            get_val(f, 2, p1, &cfg->uart_config[i].baudrate);
            p1[1] = key_stopbits;
            get_val(f, 2, p1, &cfg->uart_config[i].stopbits);
            p1[1] = key_parity;
            get_val(f, 2, p1, &cfg->uart_config[i].parity);
            p1[1] = key_master;
            get_val(f, 2, p1, &cfg->uart_config[i].master);
        }
    }
    
    p[0] = key_net_cfg;
    p[1] = key_ip_addr;
    get_val(root, 2, p, cfg->net_config.ip_addr);
    p[1] = key_netmask;
    get_val(root, 2, p, cfg->net_config.netmask);
    p[1] = key_gateway;
    get_val(root,2, p, cfg->net_config.gateway);
    p[1] = key_mac_addr;
    get_val(root, 2, p, cfg->net_config.mac_addr);
    
    p[0] = key_rs485gw_cfg;
    f = get_field(root, 1, p);
    if (f) {
        for (int i=0; i<NUM_UARTS; i++) {
            p1[0] = i;
            p1[1] = key_protocol;
            get_val(f, 2, p1, &cfg->rs485gw_config[i].protocol);
            p1[1] = key_port;
            get_val(f, 2, p1, &cfg->rs485gw_config[i].port);
            p1[1] = key_to_port;
            get_val(f, 2, p1, &cfg->rs485gw_config[i].to_port);
            p1[1] = key_to_ip;
            get_val(f, 2, p1, cfg->rs485gw_config[i].to_ip);
        }        
    }

    p[0] = key_snmp_cfg;
    
    p[1] = key_snmpv3_enable;
    get_val(root, 2, p, &cfg->snmp_config.snmpv3_enable);
    
    p[1] = key_community;
    p[2] = key_read;
    get_val(root, 3, p, cfg->snmp_config.community.read);
    p[2] = key_write;
    get_val(root, 3, p, cfg->snmp_config.community.write);

    p[1] = key_snmpv3_users;
    f = get_field(root, 2, p);
    if (f) {
        for (int i=0; i<2; i++) {
            p1[0] = i;
            p1[1] = key_snmp_username;
            get_val(f, 2, p1, cfg->snmp_config.users[i].username);
            p1[1] = key_auth_key;
            get_val(f, 2, p1, cfg->snmp_config.users[i].auth_key);
            p1[1] = key_priv_key;
            get_val(f, 2, p1, cfg->snmp_config.users[i].priv_key);
        }
    }
    
    p[0] = key_users;
    f = get_field(root, 1, p);
    if (f) {
        for (int i=0; i<8; i++) {
            p1[0] = i;
            p1[1] = key_username;
            get_val(f, 2, p1, cfg->users[i].name);
            if (cfg->users[i].name[0]==0) break;
            p1[1] = key_sshpass;
            get_val(f, 2, p1, cfg->users[i].sshpass);
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
    fd = fopen("sec23.bin", "rb"); 
    if (fd) {
        ptr = fread(cfg_hdr_ptr, sizeof(uint8_t), MEMB_SIZE, fd);
        fclose(fd);
    }
    root = (field_t *)memb;
    
    prepare_after_read(root);
    return ERR_NONE;
}

