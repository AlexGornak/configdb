/*
 * cfg.c
 *
 *  Created on: 11 мая 2023 г.
 *      Author: ag
 */
#define VERSION         "1.2"
#include <stdio.h>
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

#define MEMB_SIZE   4096
uint8_t memb[MEMB_SIZE];
uint32_t ptr = 0;
field_t *root;

int main(int argc, char **argv)
{
    /*cfg_export(&cfg);
    print_field(root, 0);
    printf("ptr=%d\n", ptr);   
    cfg_write();*/
    cfg_read();
    printf("ptr=%d\n", ptr); 
    print_field(root, 0);
    printf("************************\n\n");
    cfg_import(&cfg1);
    printf("flash_key = %u\n", cfg1.flash_key);
    printf("version = %d\n", cfg1.version);
    printf("name = %s\n", cfg1.rs485gw_name);
    for (int i=0; i<NUM_UARTS; i++) {
        printf("uart_%d: br=%u parity=%c stopbits=%d master=%d\n", i, cfg1.uart_config[i].baudrate, \
        cfg1.uart_config[i].parity, cfg1.uart_config[i].stopbits, cfg1.uart_config[i].master);
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
    if (val) fptr->data.val = val;
    else fptr->data.head = NULL;
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
    fptr->data.val = val;
    return fptr;
}

static int add_field(field_t *parent, field_t *child)
{
    field_list_t *head;
    if (!parent) return ERR_PARAM;
    if (!child) return ERR_NONE;
    head = alloc_mem(sizeof(field_list_t));
    if (!head) return ERR_MEM;
    head->field = child;
    head->next = parent->data.head;
    parent->data.head = head;
    return ERR_NONE;
} 

static field_t *get_field_from(field_t *f, int n, int *path)
{
    int *p = path;
    field_list_t *l;
    if (n == 0) return f;
    if (f->key == *p) {
        p++; n--;
        if (n == 0) return f;
        for (l=f->data.head; l; l=l->next) {
            field_t *fld = get_field_from(l->field, n, p);
            if (fld) return fld;
        }
    }
    return NULL;
}

static field_t *get_field(int n, int *path)
{
    return get_field_from(root, n, path);
}

static void print_field(field_t *f, int level)
{
    int i;
    for (i=0; i<level; i++) printf("    ");
    printf("key=%d, type=%d\n", f->key, f->type);
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            for (field_list_t *l = f->data.head; l; l=l->next) {
                print_field(l->field, level+1);
            }
            break;
        case FT_BYTES_ARRAY:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=[");
            for (i=0; i<f->sz; i++)
                printf(" %d", ((uint8_t *)f->data.val)[i]);
            printf("]\n");
            break;
        case FT_CHAR:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val='%c'\n", *(char *)f->data.val);
            break;
        case FT_STR:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%s\n", (char *)f->data.val);
            break;
        case FT_U8:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%d\n", *(uint8_t *)f->data.val);
            break;
        case FT_U16:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%d\n", *(uint16_t *)f->data.val);
            break;
        case FT_U32:
            for (i=0; i<level+1; i++) printf("    ");
            printf("val=%u\n", *(uint32_t *)f->data.val);
            break;
        default:
            break;
    }
}

static void prepare_to_write(field_t *f)
{
    field_list_t *l, *tmp;
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            tmp = f->data.head;
            if (tmp)
                f->data.head = (field_list_t *)((pointer)tmp - (pointer)memb);
            l = tmp;
            while (l) {
                prepare_to_write(l->field);
                l->field = (field_t *)((pointer)l->field - (pointer)memb);
                tmp = l->next;
                if (tmp)
                    l->next = (field_list_t *)((pointer)tmp - (pointer)memb);
                l = tmp;
            }
            break;
        case FT_BYTES_ARRAY:
        case FT_CHAR:
        case FT_STR:
        case FT_U8:
        case FT_U16:
        case FT_U32:
            if (f->data.val)
                f->data.val = (void *)((pointer)f->data.val - (pointer)memb);
            break;
        default:
            break;
    }
}

static void prepare_after_read(field_t *f)
{
    field_list_t *l;
    switch (f->type) {
        case FT_REC:
        case FT_ARRAY:
            if (f->data.head)
                f->data.head = (field_list_t *)((pointer)f->data.head + (pointer)memb);
            l = f->data.head;
            while (l) {
                //prepare_to_write(l->field);
                l->field = (field_t *)((pointer)l->field + (pointer)memb);
                prepare_after_read(l->field);
                if (l->next)
                    l->next = (field_list_t *)((pointer)l->next + (pointer)memb);
                l = l->next;
            }
            break;
        case FT_BYTES_ARRAY:
        case FT_CHAR:
        case FT_STR:
        case FT_U8:
        case FT_U16:
        case FT_U32:
            if (f->data.val)
                f->data.val = (void *)((pointer)f->data.val + (pointer)memb);
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
    
    int p[] = {KEY_CONFIG, KEY_FLASH_KEY};
    f = get_field(2, p);
    if (f) cfg->flash_key = *(uint32_t *)f->data.val;
    
    p[1] = KEY_VERSION;
    f = get_field(2, p);
    if (f) cfg->version = *(uint16_t *)f->data.val;
    
    p[1] = KEY_NAME;
    f = get_field(2, p);
    if (f) strcpy(cfg->rs485gw_name, (char *)f->data.val);
    
    p[1] = KEY_UART_CONFIG;
    f = get_field(2, p);
    if (f) {
        int p1[3] = {KEY_UART_CONFIG, 0, 0};
        for (int i=0; i<NUM_UARTS; i++) {
            p1[1] = i;
            p1[2] = KEY_BAUDRATE;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].baudrate = *(uint32_t *)f1->data.val;
            p1[2] = KEY_STOPBITS;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].stopbits = *(uint8_t *)f1->data.val;
            p1[2] = KEY_PARITY;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].parity = *(char *)f1->data.val;
            p1[2] = KEY_MASTER;
            f1 = get_field_from(f, 3, p1);
            if (f1) cfg->uart_config[i].master = *(uint8_t *)f1->data.val;
        }
    }
    return ERR_NONE;
}

int cfg_write(void)
{
    FILE *fd;     
    prepare_to_write(root);
    fd = fopen("config.cfg", "wb"); 
    fwrite(memb, sizeof(uint8_t), ptr, fd);
    fclose(fd);
    return ERR_NONE;
}

int cfg_read(void)
{
    FILE *fd;     
    fd = fopen("config.cfg", "rb"); 
    if (fd) {
        ptr = fread(memb, sizeof(uint8_t), MEMB_SIZE, fd);
        fclose(fd);
    }
    root = (field_t *)memb;
    prepare_after_read(root);
    return ERR_NONE;

}
