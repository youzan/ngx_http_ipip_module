/*
 * Copyright (C) detailyang
 * Copyright (C) Youzan, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cJSON.h"


#define NGX_HTTP_IPIP_DATX_LITTLEEND(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define NGX_HTTP_IPIP_DATX_BIGEND(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))
#define NGX_HTTP_IPIP_PHONE_LEN 7
#define NGX_HTTP_IPIP_EMPTY_RESPONSE "{\"ret\": \"ok\", \"data\": []}"


typedef struct {
    ngx_rbtree_node_t  node;
    ngx_int_t          offset;
    ngx_int_t          len;
} ngx_http_ipip_phone_node_t;


typedef struct {
    u_char      *addr;
    u_char      *index;
    ngx_int_t    offset;
}ngx_http_ipip_ip_datx_t;


typedef struct {
    u_char            *addr;
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
} ngx_http_ipip_phone_txt_t;


typedef struct {
    ngx_file_mapping_t        ip;
    ngx_http_ipip_ip_datx_t   ip_datx;

    ngx_file_mapping_t        phone;
    ngx_http_ipip_phone_txt_t phone_txt;
} ngx_http_ipip_main_conf_t;


typedef struct {
    ngx_flag_t              enable;
} ngx_http_ipip_loc_conf_t;


static void ngx_http_ipip_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_ipip_post_conf(ngx_conf_t *cf);
static void *ngx_http_ipip_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ipip_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_ipip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ipip_ip_datx(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ipip_phone_txt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ipip_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ipip_ip_lookup(ngx_http_ipip_ip_datx_t *datx, char *ip, u_char *result);
static ngx_int_t
ngx_http_ipip_phone_lookup(ngx_http_ipip_phone_txt_t *txt, u_char *phone, u_char *result);
static ngx_int_t ngx_http_ipip_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_ipip_json_stringify(ngx_http_request_t *r,
                                    cJSON *root, u_char **buf, ssize_t *len);
static void ngx_http_ipip_rbtree_insert_value(ngx_rbtree_node_t *temp,
                    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);


static ngx_command_t ngx_http_ipip_commands[] = {
    { ngx_string("ipip_ip_datx"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_ipip_ip_datx,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("ipip_phone_txt"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_ipip_phone_txt,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("ipip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ipip_enable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ipip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_ipip_post_conf,               /* postconfiguration */

    ngx_http_ipip_create_main_conf,        /* create main configuration */
    ngx_http_ipip_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ipip_create_loc_conf,         /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t ngx_http_ipip_module = {
    NGX_MODULE_V1,
    &ngx_http_ipip_module_ctx,                 /* module context */
    ngx_http_ipip_commands,                    /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    ngx_http_ipip_exit_process,                /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_http_ipip_exit_process(ngx_cycle_t *cycle)
{
    return;
}


static ngx_int_t
ngx_http_ipip_post_conf(ngx_conf_t *cf)
{
    return NGX_OK;
}


static void *
ngx_http_ipip_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ipip_main_conf_t  *imcf;

    imcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_main_conf_t));
    if (imcf == NULL) {
        return NULL;
    }

    return imcf;
}


static char *
ngx_http_ipip_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static void *
ngx_http_ipip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ipip_loc_conf_t  *ilcf;

    ilcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_loc_conf_t));
    if (ilcf == NULL) {
        return NULL;
    }

    ilcf->enable = NGX_CONF_UNSET;

    return ilcf;
}


static char *
ngx_http_ipip_ip_datx(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ipip_main_conf_t  *imcf = conf;

    ngx_int_t                  n;
    ngx_str_t                 *value;
    struct stat                s;

    if (imcf->ip.name != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    imcf->ip.name = value[1].data;

    imcf->ip.fd = ngx_open_file(imcf->ip.name, NGX_FILE_RDONLY, 0, 0);
    if (imcf->ip.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
         ngx_open_file_n " \"%s\" failed",
         &imcf->ip.name);
        return NGX_CONF_ERROR;
    }

    if (fstat(imcf->ip.fd, &s) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "fstat \"%s\" failed", &imcf->ip.name);
        return NGX_CONF_ERROR;
    }

    imcf->ip.size = s.st_size;
    imcf->ip.log = cf->log;

    imcf->ip.addr = ngx_pcalloc(cf->pool, s.st_size);
    if (imcf->ip.addr == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "try to ngx_pcalloc \"%s\" %d bytes failed", imcf->ip.name, s.st_size);
        return NGX_CONF_ERROR;
    }

    n = read(imcf->ip.fd, imcf->ip.addr, s.st_size);
    if (n != s.st_size) {
        close(imcf->ip.fd);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "try to read \"%s\" %d bytes failed", imcf->ip.name, s.st_size);
        return NGX_CONF_ERROR;
    }

    imcf->ip_datx.addr = imcf->ip.addr;
    imcf->ip_datx.offset = NGX_HTTP_IPIP_DATX_BIGEND(imcf->ip_datx.addr);
    imcf->ip_datx.index = imcf->ip_datx.addr + 4;

    close(imcf->ip.fd);

    return NGX_CONF_OK;
}


static char *
ngx_http_ipip_phone_txt(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ipip_main_conf_t  *imcf = conf;

    u_char                    *p;
    ngx_str_t                 *value;
    ngx_int_t                  n;
    ngx_uint_t                 i, lasti;
    struct stat                s;
    ngx_http_ipip_phone_node_t *pnode;

    if (imcf->phone.name != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_conf_full_name(cf->cycle, &value[1], 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    imcf->phone.name = value[1].data;

    imcf->phone.fd = ngx_open_file(imcf->phone.name, NGX_FILE_RDONLY, 0, 0);
    if (imcf->phone.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
         ngx_open_file_n " \"%s\" failed",
          imcf->phone.name);
        return NGX_CONF_ERROR;
    }

    if (fstat(imcf->phone.fd, &s) == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "fstat \"%s\" failed",  imcf->phone.name);
        return NGX_CONF_ERROR;
    }

    imcf->phone.size = s.st_size;
    imcf->phone.log = cf->log;

    imcf->phone.addr = ngx_pcalloc(cf->pool, s.st_size);
    if (imcf->phone.addr == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "try to ngx_pcalloc \"%s\" %d bytes failed", imcf->phone.name, s.st_size);
        return NGX_CONF_ERROR;
    }

    n = read(imcf->phone.fd, imcf->phone.addr, s.st_size);
    if (n != s.st_size) {
        close(imcf->phone.fd);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
            "try to read \"%s\" %d bytes failed", imcf->phone.name, s.st_size);
        return NGX_CONF_ERROR;
    }

    imcf->phone_txt.addr = imcf->phone.addr;
    ngx_rbtree_init(&imcf->phone_txt.rbtree, &imcf->phone_txt.sentinel,
                    ngx_http_ipip_rbtree_insert_value);

    lasti = 0;
    p = imcf->phone.addr;

    for (i = 0; i < imcf->phone.size; i ++) {
        if (p[i] != LF) {
            continue;
        }

        pnode = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_phone_node_t));
        if (pnode == NULL) {
            return NGX_CONF_ERROR;
        }

        pnode->offset = lasti;
        pnode->len = i - lasti;
        pnode->node.key = ngx_atoi(&p[lasti], 7);
        lasti = i + 1;

        ngx_rbtree_insert(&imcf->phone_txt.rbtree, &pnode->node);
    }

    close(imcf->phone.fd);

    return NGX_CONF_OK;
}


static void
ngx_http_ipip_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_http_ipip_phone_node_t    *pnode, *pnodet;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            pnode = (ngx_http_ipip_phone_node_t *) &node->color;
            pnodet = (ngx_http_ipip_phone_node_t *) &temp->color;

            p = pnode->offset < pnodet->offset ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static char *
ngx_http_ipip_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ipip_loc_conf_t  *ilcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;

    if (ilcf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        ilcf->enable = 1;
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_ipip_handler;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        return NGX_CONF_OK;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_ipip_phone_lookup(ngx_http_ipip_phone_txt_t *txt, u_char *phone, u_char *result)
{
    ngx_uint_t                     hash;
    ngx_rbtree_t                  *rbtree;
    ngx_rbtree_node_t             *node, *sentinel;
    ngx_http_ipip_phone_node_t    *pnode;

    if (txt->addr == NULL) {
        return NGX_ERROR;
    }

    rbtree = &txt->rbtree;
    node = rbtree->root;
    sentinel = rbtree->sentinel;
    hash = ngx_atoi(phone, NGX_HTTP_IPIP_PHONE_LEN);

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        pnode = (ngx_http_ipip_phone_node_t *)node;
        ngx_memcpy((void *)result, txt->addr + pnode->offset, pnode->len);

        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_ipip_ip_lookup(ngx_http_ipip_ip_datx_t *datx, char *ip, u_char *result)
{
    ngx_uint_t ips[4];
    ngx_uint_t ip_prefix_value, ip2long_value, start, max_comp_len, index_offset, index_length;

    if (datx->addr == NULL) {
        return NGX_ERROR;
    }

    if (sscanf(ip, "%u.%u.%u.%u", (unsigned int *)&ips[0], (unsigned int *)&ips[1],
               (unsigned int *)&ips[2], (unsigned int *)&ips[3]) != 4)
    {
        return NGX_ERROR;
    }

    ip_prefix_value = ips[0] * 256 + ips[1];
    ip2long_value = NGX_HTTP_IPIP_DATX_BIGEND(ips);
    start = datx->addr[4 + ip_prefix_value];
    max_comp_len = datx->offset - 262144 - 4;
    index_offset = 0;
    index_length = 0;

    for (start = start * 9 + 262144; start < max_comp_len; start += 9) {

        if (NGX_HTTP_IPIP_DATX_BIGEND(datx->index + start) >= ip2long_value) {
            index_offset = NGX_HTTP_IPIP_DATX_LITTLEEND(datx->index + start + 4) & 0x00FFFFFF;
            index_length = (datx->index[start + 7] << 8) + datx->index[start + 8];
            break;
        }
    }

    ngx_memcpy(result, datx->addr + datx->offset + index_offset - 262144, index_length);
    result[index_length] = '\0';

    return NGX_OK;
}


static ngx_int_t
ngx_http_ipip_arg(u_char *begin, u_char *end, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    p = begin;
    last = end;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == begin || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = last;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_ipip_ip_handler(ngx_http_request_t *r)
{
    cJSON                     *root, *data;
    u_char                    *result, *lastp, *p, *last, *buf, *tmpbuf;
    ssize_t                    len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                  arg;
    ngx_chain_t                out;
    ngx_http_ipip_main_conf_t *imcf;

    imcf = ngx_http_get_module_main_conf(r, ngx_http_ipip_module);

    result = ngx_pcalloc(r->pool, 512);
    if (result == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = r->args.data;
    last = r->args.data + r->args.len;

    rc = ngx_http_ipip_arg(p, last, (u_char *)"ip", 2, &arg);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /*

    {
        "ret": "ok",              // ret 值为 ok 时 返回 data 数据 为err时返回msg数据
        "data": [
            "中国",                // 国家
            "天津",                // 省会或直辖市（国内）
            "天津",                // 地区或城市 （国内）
            "",                   // 学校或单位 （国内）
            "鹏博士",              // 运营商字段（只有购买了带有运营商版本的数据库才会有）
            "39.128399",          // 纬度     （每日版本提供）
            "117.185112",         // 经度     （每日版本提供）
            "Asia/Shanghai",      // 时区一, 可能不存在  （每日版本提供）
            "UTC+8",              // 时区二, 可能不存在  （每日版本提供）
            "120000",             // 中国行政区划代码    （每日版本提供）
            "86",                 // 国际电话代码        （每日版本提供）
            "CN",                 // 国家二位代码        （每日版本提供）
            "AP"                  // 世界大洲代码        （每日版本提供）
        ]
    }

    */

    rc = ngx_http_ipip_ip_lookup(&imcf->ip_datx, (char *)arg.data, result);
    if (rc != NGX_OK) {
        
        buf = ngx_pcalloc(r->pool, sizeof(NGX_HTTP_IPIP_EMPTY_RESPONSE));
        if (buf == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memcpy(buf, NGX_HTTP_IPIP_EMPTY_RESPONSE, sizeof(NGX_HTTP_IPIP_EMPTY_RESPONSE));

    } else {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "ret", "ok");
        cJSON_AddItemToObject(root, "data", data = cJSON_CreateArray());

        lastp = p = result;
        for (;*p != '\0'; p++) {
            
            if (*p == '\t') {
                
                tmpbuf = ngx_pcalloc(r->pool, p - lastp);
                if (tmpbuf == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                
                ngx_cpystrn(tmpbuf, lastp, p - lastp + 1);
                cJSON_AddStringToObject(data, "dummpy", (char *)tmpbuf);
                lastp = p + 1;
            }
        }

        if (lastp != p) {
            
            tmpbuf = ngx_pcalloc(r->pool, p - lastp);
            if (tmpbuf == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            ngx_cpystrn(tmpbuf, lastp, p - lastp + 1);
            cJSON_AddStringToObject(data, "dummpy", (char *)tmpbuf);
        }

        ngx_http_ipip_json_stringify(r, root, &buf, &len);
    }

    r->headers_out.content_length_n = strlen((char *)buf);
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;
    b->pos = buf;
    b->last = buf + r->headers_out.content_length_n;
    b->memory = 1;
    b->last_buf = 1;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_ipip_phone_handler(ngx_http_request_t *r)
{
    cJSON                     *root, *data;
    u_char                    *result, *p, *lastp, *last, *buf, *tmpbuf;
    ssize_t                    len;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_str_t                  arg;
    ngx_chain_t                out;
    ngx_http_ipip_main_conf_t *imcf;

    imcf = ngx_http_get_module_main_conf(r, ngx_http_ipip_module);

    result = ngx_pcalloc(r->pool, 512);
    if (result == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = r->args.data;
    last = r->args.data + r->args.len;

    rc = ngx_http_ipip_arg(p, last, (u_char *)"phone", 5, &arg);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /*

    {
        "ret": "ok",              // ret 值为 ok 时 返回 data 数据 为err时返回msg数据
        "data": [
            "浙江",                // 省会
            "杭州",                // 市级
            ""                    //  运营商
        ]
    }

    */

    rc = ngx_http_ipip_phone_lookup(&imcf->phone_txt, arg.data, result);
    if (rc != NGX_OK) {
        
        buf = ngx_pcalloc(r->pool, sizeof(NGX_HTTP_IPIP_EMPTY_RESPONSE));
        if (buf == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memcpy(buf, NGX_HTTP_IPIP_EMPTY_RESPONSE, sizeof(NGX_HTTP_IPIP_EMPTY_RESPONSE));

    } else {
        root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "ret", "ok");
        cJSON_AddItemToObject(root, "data", data = cJSON_CreateArray());

        lastp = p = result + NGX_HTTP_IPIP_PHONE_LEN + 1;
        for (;*p != '\0'; p++) {
            
            if (*p == '\t') {
                
                tmpbuf = ngx_pcalloc(r->pool, p - lastp);
                if (tmpbuf == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                
                ngx_cpystrn(tmpbuf, lastp, p - lastp + 1);
                cJSON_AddStringToObject(data, "dummpy", (char *)tmpbuf);
                lastp = p + 1;
            }
        }

        if (lastp != p) {
            
            tmpbuf = ngx_pcalloc(r->pool, p - lastp);
            if (tmpbuf == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            ngx_cpystrn(tmpbuf, lastp, p - lastp + 1);
            cJSON_AddStringToObject(data, "dummpy", (char *)tmpbuf);
        }

        ngx_http_ipip_json_stringify(r, root, &buf, &len);
    }

    r->headers_out.content_length_n = strlen((char *)buf);
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;
    b->pos = buf;
    b->last = buf + r->headers_out.content_length_n;
    b->memory = 1;
    b->last_buf = 1;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_ipip_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_strncasecmp(r->uri.data, (u_char *)"/ip", 3) == 0) {
        return ngx_http_ipip_ip_handler(r);

    } else if (ngx_strncasecmp(r->uri.data, (u_char *)"/phone", 6) == 0){
        return ngx_http_ipip_phone_handler(r);

    } else {
        return NGX_HTTP_NOT_FOUND;
    }

}


static ngx_int_t
ngx_http_ipip_json_stringify(ngx_http_request_t *r, cJSON *root, u_char **buf, ssize_t *len)
{
    char *out = NULL;

    out = cJSON_Print(root);
    *len = strlen(out) + 64;
    
    *buf = ngx_pcalloc(r->pool, *len);
    if (*buf == NULL) {
        goto ERROR;
    }

    if (!cJSON_PrintPreallocated(root, (char *)*buf, *len, 1)) {
        goto ERROR;
    }

    return NGX_OK;

ERROR:

    free(out);
    return NGX_ERROR;
}
