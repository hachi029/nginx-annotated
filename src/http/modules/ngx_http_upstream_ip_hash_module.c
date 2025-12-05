
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


//算法数据对象， ip_hash的per request负载均衡数据的结构体
typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp;         //round robin的per request负载均衡数据（因为是基于round_robin的），必须是第一个

    ngx_uint_t                         hash;    /* 根据客户端IP计算所得的hash值 */

    u_char                             addrlen; /* 使用客户端IP的后三个字节来计算hash值 */
    u_char                            *addr;    /* 客户端的IP */

    u_char                             tries;   /* 已经尝试了多少次 */

    ngx_event_get_peer_pt              get_rr_peer; /* round robin算法的peer.get函数 */
} ngx_http_upstream_ip_hash_peer_data_t;


static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_ip_hash_commands[] = {

    //如果有指令ip_hash，则选择ip_hash负载均衡算法
    { ngx_string("ip_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_http_upstream_ip_hash,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


/**
 * https://www.kancloud.cn/digest/sknginx/130032
 * 
 * ip_hash算法的原理很简单，根据请求所属的客户端IP计算得到一个数值，然后把请求发往该数值对应的后端。
 * 所以同一个客户端的请求，都会发往同一台后端，除非该后端不可用了。ip_hash能够达到保持会话的效果。
 * ip_hash是基于round robin的，判断后端是否可用的方法是一样的。
 */
ngx_module_t  ngx_http_upstream_ip_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_ip_hash_module_ctx, /* module context */
    ngx_http_upstream_ip_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];


/**
 * 在执行ngx_http_upstream_module的init main conf函数时，会调用所有upstream块的初始化函数。
 * 对于使用ip_hash的upstream块，其初始化函数（peer.init_upstream）就是ngx_http_upstream_init_ip_hash
 * 主要工作：
 *  调用默认的初始化函数ngx_http_upstream_init_round_robin来创建和初始化后端集群，保存该upstream块的数据
 *  指定初始化请求的负载均衡数据的函数peer.init
 * 
 */
static ngx_int_t
ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    //调用round robin函数初始化IP地址列表
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    //设置自己的算法初始化函数
    us->peer.init = ngx_http_upstream_init_ip_hash_peer;

    return NGX_OK;
}


/**
 * https://www.kancloud.cn/digest/understandingnginx/202607
 * 
 * IP 哈希策略选择后端服务器时，将来自同一个 IP 地址的客户端请求分发到同一台后端服务器处理。在 Nginx 中，IP 哈希策略的一些初始化工作是基于加权轮询策略的，这样减少了一些工作。
 *
 *  Nginx 使用 IP 哈希负载均衡策略时，在进行策略选择之前由 ngx_http_upstream_init_ip_hash 函数进行全局初始化工作，其实该函数也是调用加权轮询策略的全局初始化函数。
 *  当一个客户端请求过来时，Nginx 将调用 ngx_http_upstream_init_ip_hash_peer() 为选择后端服务器处理该请求做初始化工作。
 *  
 *  在多次哈希选择失败后，Nginx 会将选择策略退化到加权轮询。
 * 
 *  函数会在选择后端服务器时计算客户端请求 IP 地址的哈希值，并根据哈希值得到被选中的后端服务器，判断其是否可用，如果可用则保存服务器地址，若不可用则在上次哈希选择结果基础上再次进行哈希选择。如果哈希选择失败次数达到 20 次以上，此时回退到采用轮询策略进行选择
 */
static ngx_int_t
ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    struct sockaddr_in                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    ngx_http_upstream_ip_hash_peer_data_t  *iphp;

     /* 创建ip_hash的per request负载均衡数据的实例 */
    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }

    /* 首先调用round robin的per request负载均衡数据的初始化函数，
    * 创建和初始化round robin的per request负载均衡数据实例，即iphp->rrp。
    */
    r->upstream->peer.data = &iphp->rrp;

     /* 调用加权轮询策略的初始化函数,得到配置里的ip地址列表 */
    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 重新指定peer.get，用于从集群中选取一台后端服务器 */
    r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;

     /* 客户端的地址类型 */
    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;
        iphp->addrlen = 3;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;     /* 保存round robin的peer.get函数 */

    return NGX_OK;
}


/**
 * 选择后端服务器，是IP散列算法的具体实现
 * 根据ip地址计算散列值，然后从列表中选择一个地址
 * 
 * 采用ip_hash算法，从集群中选出一台后端来处理本次请求。 选定后端的地址保存在pc->sockaddr，pc为主动连接
 * 
 * 函数的返回值：
 * NGX_DONE：选定一个后端，和该后端的连接已经建立。之后会直接发送请求。
 * NGX_OK：选定一个后端，和该后端的连接尚未建立。之后会和后端建立连接。
 * NGX_BUSY：所有的后端（包括备份集群）都不可用。之后会给客户端发送502（Bad Gateway）。
 */
static ngx_int_t
ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    ngx_http_upstream_rr_peers_rlock(iphp->rrp.peers);

     /* 若重试连接的次数 tries 大于 20，或 只有一台后端服务器，则直接调用加权轮询策略选择当前后端服务器处理请求 */
    if (iphp->tries > 20 || iphp->rrp.peers->number < 2) {
        //退化为round robin
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }

#if (NGX_HTTP_UPSTREAM_ZONE)
    if (iphp->rrp.peers->config && iphp->rrp.config != *iphp->rrp.peers->config)
    {
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, &iphp->rrp);
    }
#endif

    now = ngx_time();

    pc->cached = 0;         //不使用磁盘缓存
    pc->connection = NULL;  //尚未连接

    hash = iphp->hash;      /* 本次选取的初始hash值 */

    for ( ;; ) {

        /* 根据客户端IP、本次选取的初始hash值，计算得到本次最终的hash值 */
        for (i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
            hash = (hash * 113 + iphp->addr[i]) % 6271;
        }

        /* total_weight和weight都是固定值 */
        w = hash % iphp->rrp.peers->total_weight;
        peer = iphp->rrp.peers->peer;       /* 第一台后端 */
        p = 0;

        while (w >= peer->weight) {
            w -= peer->weight;
            peer = peer->next;
            p++;
        }

        /* 检查第此后端在状态位图中对应的位，为1时表示不可用 */
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (iphp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        ngx_http_upstream_rr_peer_lock(iphp->rrp.peers, peer);

        /* 检查后端是否永久不可用 */
        if (peer->down) {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        /* 在一段时间内，如果此后端服务器的失败次数，超过了允许的最大值，那么不允许使用此后端了 */
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
            goto next;
        }

        break;

    next:

        /* 增加已尝试的次数，如果超过20次，则使用轮询的方式来选取后端 */
        if (++iphp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, &iphp->rrp);
        }
    }

    iphp->rrp.current = peer;   /* 选定的可用后端 */
    ngx_http_upstream_rr_peer_ref(iphp->rrp.peers, peer);

    /* 保存选定的后端服务器的地址，之后会向这个地址发起连接 */
    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

     /* 更新checked时间 */
    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_http_upstream_rr_peer_unlock(iphp->rrp.peers, peer);
    ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    iphp->rrp.tried[n] |= m;        /* 对于此请求，如果之后需要再次选取后端，不能再选取这个后端了 */
    iphp->hash = hash;              /* 保存hash值，下次可能还会用到 */

    return NGX_OK;
}


/**
 * ip_hash配置指令解析，设置算法的入口函数
 * 
 * 指定初始化此upstream块的函数peer.init_upstream
 * 
 * 指定此upstream块中server指令支持的属性
 * 
 */
static char *
ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;

     /* 获取对应的upstream配置块 */
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    //如果已经设置了
    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

     /* 指定初始化此upstream块的函数 */
    uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;

     /* 指定此upstream块中server指令支持的属性 */
    uscf->flags = NGX_HTTP_UPSTREAM_CREATE              //检查是否重复创建，以及必要的参数是否填写
                  |NGX_HTTP_UPSTREAM_MODIFY             //
                  |NGX_HTTP_UPSTREAM_WEIGHT             //server指令支持weight属性
                  |NGX_HTTP_UPSTREAM_MAX_CONNS          //server指令支持max_conns属性
                  |NGX_HTTP_UPSTREAM_MAX_FAILS          //server指令支持max_fails属性
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT       //server指令支持fail_timeout属性
                  |NGX_HTTP_UPSTREAM_DOWN;              //server指令支持down属性

    return NGX_CONF_OK;
}
