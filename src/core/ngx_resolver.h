
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_RESOLVER_H_INCLUDED_
#define _NGX_RESOLVER_H_INCLUDED_


#define NGX_RESOLVE_A         1
#define NGX_RESOLVE_CNAME     5
#define NGX_RESOLVE_PTR       12
#define NGX_RESOLVE_MX        15
#define NGX_RESOLVE_TXT       16
#if (NGX_HAVE_INET6)
#define NGX_RESOLVE_AAAA      28
#endif
#define NGX_RESOLVE_SRV       33
#define NGX_RESOLVE_DNAME     39

#define NGX_RESOLVE_FORMERR   1
#define NGX_RESOLVE_SERVFAIL  2
#define NGX_RESOLVE_NXDOMAIN  3
#define NGX_RESOLVE_NOTIMP    4
#define NGX_RESOLVE_REFUSED   5
#define NGX_RESOLVE_TIMEDOUT  NGX_ETIMEDOUT


#define NGX_NO_RESOLVER       (void *) -1

#define NGX_RESOLVER_MAX_RECURSION    50


typedef struct ngx_resolver_s  ngx_resolver_t;


/**
 * 代表一个与DNS服务器的连接
 */
typedef struct {
    ngx_connection_t         *udp;
    ngx_connection_t         *tcp;      // tcp 连接的connection
    struct sockaddr          *sockaddr; // resolver 地址
    socklen_t                 socklen;
    ngx_str_t                 server;   // resolver域名
    ngx_log_t                 log;
    ngx_buf_t                *read_buf;     // tcp 读缓存区
    ngx_buf_t                *write_buf;    // tcp 写缓存区
    ngx_resolver_t           *resolver;
} ngx_resolver_connection_t;


typedef struct ngx_resolver_ctx_s  ngx_resolver_ctx_t;

typedef void (*ngx_resolver_handler_pt)(ngx_resolver_ctx_t *ctx);


typedef struct {
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
} ngx_resolver_addr_t;


typedef struct {
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;
} ngx_resolver_srv_t;


typedef struct {
    ngx_str_t                 name;
    u_short                   priority;
    u_short                   weight;
    u_short                   port;

    ngx_resolver_ctx_t       *ctx;
    ngx_int_t                 state;

    ngx_uint_t                naddrs;
    ngx_addr_t               *addrs;
} ngx_resolver_srv_name_t;


/**
 * 代表一个域名解析的结果，会被加入到红黑树中进行缓存
 */
typedef struct {
    ngx_rbtree_node_t         node;    //红黑树节点 
    ngx_queue_t               queue;

    /* PTR: resolved name, A: name to resolve */
    //要解析的域名
    u_char                   *name;

#if (NGX_HAVE_INET6)
    /* PTR: IPv6 address to resolve (IPv4 address is in rbtree node key) */
    struct in6_addr           addr6;
#endif

    // 要解析的域名的长度
    u_short                   nlen;
    // 发送dns解析命令的长度
    u_short                   qlen;

    // dns解析命令字符串
    u_char                   *query;
#if (NGX_HAVE_INET6)
    u_char                   *query6;
#endif

    union {
        in_addr_t             addr;
        in_addr_t            *addrs;
        u_char               *cname;
        ngx_resolver_srv_t   *srvs;
    } u;

    u_char                    code;
    u_short                   naddrs;
    u_short                   nsrvs;
    u_short                   cnlen;

#if (NGX_HAVE_INET6)
    union {
        struct in6_addr       addr6;
        struct in6_addr      *addrs6;
    } u6;

    u_short                   naddrs6;
#endif

    time_t                    expire;
    time_t                    valid;
    uint32_t                  ttl;

    // 是否通过tcp方式方法查询请求
    unsigned                  tcp:1;
#if (NGX_HAVE_INET6)
    unsigned                  tcp6:1;
#endif

    // dns域名服务器地址下标
    ngx_uint_t                last_connection;

    //其他相同域名的解析请求等待队列
    ngx_resolver_ctx_t       *waiting;
} ngx_resolver_node_t;


/**
 * https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver
 * 标识一个resolve配置指令的解析结果
 * 
 * resolve 可以配置多个DNS服务器地址，解析域名时会使用这些DNS服务器地址进行轮询。
 */
struct ngx_resolver_s {
    /* has to be pointer because of "incomplete type" */
    ngx_event_t              *event;
    void                     *dummy;
    ngx_log_t                *log;

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;

    //resolver服务地址。 元素类型为 ngx_resolver_connection_t, 每个dns服务器一条连接，用于轮询负载均衡
    /* simple round robin DNS peers balancer */
    ngx_array_t               connections;
    ngx_uint_t                last_connection;

    ngx_rbtree_t              name_rbtree;
    ngx_rbtree_node_t         name_sentinel;

    ngx_rbtree_t              srv_rbtree;
    ngx_rbtree_node_t         srv_sentinel;

    ngx_rbtree_t              addr_rbtree;
    ngx_rbtree_node_t         addr_sentinel;

    ngx_queue_t               name_resend_queue;
    ngx_queue_t               srv_resend_queue;
    ngx_queue_t               addr_resend_queue;

    ngx_queue_t               name_expire_queue;
    ngx_queue_t               srv_expire_queue;
    ngx_queue_t               addr_expire_queue;

    //标识是否解析ipv4地址
    unsigned                  ipv4:1;

#if (NGX_HAVE_INET6)
    //标识是否解析ipv4地址
    unsigned                  ipv6:1;
    ngx_rbtree_t              addr6_rbtree;
    ngx_rbtree_node_t         addr6_sentinel;
    ngx_queue_t               addr6_resend_queue;
    ngx_queue_t               addr6_expire_queue;
#endif

    time_t                    resend_timeout;
    time_t                    tcp_timeout;
    time_t                    expire;
    //dns解析结果的有效时间
    time_t                    valid;

    ngx_uint_t                log_level;
};


/**
 * 运行时域名解析上下文， 由ngx_resolve_start方法创建
 */
struct ngx_resolver_ctx_s {
    ngx_resolver_ctx_t       *next;
    ngx_resolver_t           *resolver;
    ngx_resolver_node_t      *node;

    /* event ident must be after 3 pointers as in ngx_connection_t */
    ngx_int_t                 ident;

    //解析状态，如 NGX_RESOLVE_TIMEDOUT
    ngx_int_t                 state;
    //要解析的域名
    ngx_str_t                 name;
    ngx_str_t                 service;

    time_t                    valid;
    ngx_uint_t                naddrs;
    // 解析的IP
    ngx_resolver_addr_t      *addrs;
    // 如果域名本来就是ip，则把ip解析到该内存。不用向dns服务器发起请求
    ngx_resolver_addr_t       addr;
    struct sockaddr_in        sin;

    ngx_uint_t                count;
    ngx_uint_t                nsrvs;
    ngx_resolver_srv_name_t  *srvs;

    //域名解析结束的回调函数
    ngx_resolver_handler_pt   handler;
    void                     *data;
    //解析超时时间
    ngx_msec_t                timeout;

    //不用向dns服务器发起查询，也可以说是快速的同步的。
    unsigned                  quick:1;
    unsigned                  async:1;
    unsigned                  cancelable:1;
    ngx_uint_t                recursion;
    // 只用做超时ngx_resolver_set_timeout函数初始化
    ngx_event_t              *event;
};


// 创建域名解析结构体，用于后续的域名解析
ngx_resolver_t *ngx_resolver_create(ngx_conf_t *cf, ngx_str_t *names,
    ngx_uint_t n);
// 初始化域名解析上下文ngx_resolver_ctx_t
ngx_resolver_ctx_t *ngx_resolve_start(ngx_resolver_t *r,
    ngx_resolver_ctx_t *temp);
// 构建dns查询并发起查询请求
ngx_int_t ngx_resolve_name(ngx_resolver_ctx_t *ctx);
// dns查询结束，清理资源
void ngx_resolve_name_done(ngx_resolver_ctx_t *ctx);
ngx_int_t ngx_resolve_addr(ngx_resolver_ctx_t *ctx);
void ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx);
char *ngx_resolver_strerror(ngx_int_t err);


#endif /* _NGX_RESOLVER_H_INCLUDED_ */
