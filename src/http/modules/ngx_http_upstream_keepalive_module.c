
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 本模块srv级别配置结构体
 */
typedef struct {
    //keepalive connections; 配置值， 最大的空闲连接数
    ngx_uint_t                         max_cached;
    //keepalive_requests 配置值， 一条连接上的最大请求数量
    ngx_uint_t                         requests;
    //keepalive_time 配置指令值。一条连接最长存活时间，默认1h
    ngx_msec_t                         time;
    //keepalive_timeout 配置指令值。一条连接最大空闲时间。默认60s
    ngx_msec_t                         timeout;

    //双向队列，元素类型为表示一条连接的ngx_http_upstream_keepalive_cache_t
    //存放的是和idle connection关联的节点。每个节点代表一个有效的连接
    ngx_queue_t                        cache;
    //存放的是可用的ngx_http_upstream_keepalive_cache_t节点。这些节点没有和idle connection关联
    ngx_queue_t                        free;

    //init_upstream
    ngx_http_upstream_init_pt          original_init_upstream;
    //init_peer指针
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_upstream_keepalive_srv_conf_t;


/**
 * 双向队列节点，代表一条空闲连接
 */
typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    //双向队列
    ngx_queue_t                        queue;
    //对应的ngx_connection_t结构体
    ngx_connection_t                  *connection;

    //连接上游地址
    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

} ngx_http_upstream_keepalive_cache_t;


/**
 * 本模块的peer.data结构体
 */
typedef struct {
    //本模块的srv配置结构体
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    //upstream
    ngx_http_upstream_t               *upstream;

    //保存原peer.data
    void                              *data;

    //保存原peer.get
    ngx_event_get_peer_pt              original_get_peer;
    //保存原peer.free
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_http_upstream_keepalive_peer_data_t;


static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("keepalive_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, time),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { ngx_string("keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


/**
 * upstream_keepalive
 * https://github.com/vislee/leevis.com/issues/137
 * 
 * https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive
 */
ngx_module_t  ngx_http_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_keepalive_module_ctx, /* module context */
    ngx_http_upstream_keepalive_commands,    /* module directives */
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


/**
 *  在执行ngx_http_upstream_module的init main conf函数时，会调用所有upstream块的初始化函数。
 */
static ngx_int_t
ngx_http_upstream_init_keepalive(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                               i;
    ngx_http_upstream_keepalive_srv_conf_t  *kcf;
    ngx_http_upstream_keepalive_cache_t     *cached;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    ngx_conf_init_msec_value(kcf->time, 3600000);
    ngx_conf_init_msec_value(kcf->timeout, 60000);
    ngx_conf_init_uint_value(kcf->requests, 1000);

    // 调用原来的初始化函数
    if (kcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    // 保存原来上游节点初始化函数
    kcf->original_init_peer = us->peer.init;

    //重置为本模块的方法
    us->peer.init = ngx_http_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */

    cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    // 初始化存放连接的双向链表
    ngx_queue_init(&kcf->cache);
    // 初始化空闲缓存链表
    ngx_queue_init(&kcf->free);

    //初始所有节点都为free节点
    for (i = 0; i < kcf->max_cached; i++) {
        ngx_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NGX_OK;
}


/**
 * 在ngx_http_upstream_init函数中调用ngx_http_upstream_init_request初始化上游的请求。
 * 首先会根据配置找到一组上游服务，即一个upstream配置块。找到以后会调用上游的初始化函数，即：uscf->peer.init。 
 * 因在upstream块配置了keepalive指令，在指令解析该回调函数被改为ngx_http_upstream_init_keepalive_peer
 */
static ngx_int_t
ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    //调用原init_peer
    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;                  // 保存了上游服务器地址
    kp->original_get_peer = r->upstream->peer.get;      // 原获取上游服务器ip的函数
    kp->original_free_peer = r->upstream->peer.free;

    // 覆盖上游服务器地址结构体，和上游服务器ip获取函数等。
    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    return NGX_OK;
}


// 获取一个上游地址的回调函数
// 在ngx_event_connect_peer函数中被调用
// 如果返回NGX_OK就继续执行建立到上游的tcp链接
// 返回NGX_DONE 就直接返回，不需要建立tcp链接。
static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    // 调用原来获取上游服务器ip的函数
    // 如果没有配置负载均衡策略的，则该函数默认是round robin模块赋值的ngx_http_upstream_get_round_robin_peer函数
    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    //遍历cache双向队列
    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            // 从cache链表删除
            ngx_queue_remove(q);
            // 从缓存的空闲链接链表找到了对应地址的链接
            ngx_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    //idle设为0
    c->idle = 0;
    //连接上已经发送出去的字节数
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


// 释放上游回调函数，在ngx_http_upstream_finalize_request函数中被调用。
static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof         // 上游关闭链接
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    //如果处理的请求数已经超过了限制
    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    //如果连接存活时间超过了限制
    if (ngx_current_msec - c->start_time > kp->conf->time) {
        goto invalid;
    }

    if (!u->keepalive) {
        // 不需要支持长链接的
        goto invalid;
    }

    if (!u->request_body_sent) {
        // 请求body没有转发到上游的
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
         // nginx work进程需要退出的
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        // 可读事件添加成边沿触发的，监听上游关闭操作
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    //从free双向队列中取出一个空闲的ngx_http_upstream_keepalive_cache_t结构体，与当前连接关联，放入到cache双向链表头部
    
    //如果free为空，标识没有空闲的ngx_http_upstream_keepalive_cache_t结构体结构体了。也就是idle连接超过限制了
    if (ngx_queue_empty(&kp->conf->free)) {

        //从cache中取出最老的节点
        q = ngx_queue_last(&kp->conf->cache);
        //将节点从双向队列尾部移除
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        //关闭该节点关联的连接
        ngx_http_upstream_keepalive_close(item->connection);

    } else {
        //free队列非空，还有未使用的ngx_http_upstream_keepalive_cache_t结构体，则取出一个
        q = ngx_queue_head(&kp->conf->free);
        //将其从队列中移除
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    //添加到cache头部
    ngx_queue_insert_head(&kp->conf->cache, q);

    //关联当前连接
    item->connection = c;

    // 这一步赋值NULL是非常有意义的
    // 否则在ngx_http_upstream_finalize_request函数中还会关闭链接的
    pc->connection = NULL;

    c->read->delayed = 0;
    //添加idle超时定时器
    ngx_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    // 空闲时上游可读回调函数
    c->read->handler = ngx_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    //invalid时，不缓存此连接，调用original_free_peer释放连接
    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


/**
 * 空闲时上游可读回调函数
 */
static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;
    ngx_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    //如果是连接关闭或超时
    if (c->close || c->read->timedout) {
        goto close;
    }

    // 读一个字节，检查结果。
    // 使用了MSG_PEEK 该字节还会保存在套接字缓存区不会被删掉，下次读还可以读到。
    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        // 如果是资源暂时不可用，则继续添加到可读回调中等待后续可读回调的触发
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    // 关闭链接
    ngx_http_upstream_keepalive_close(c);

    // 缓存结构体放回到free链表中
    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


/**
 * 关闭连接
 */
static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


/**
 * 创建srv级别配置结构体
 */
static void *
ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */

    conf->time = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->requests = NGX_CONF_UNSET_UINT;

    return conf;
}


/**
 * https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive
 * 
 * keepalive connections;
 * 
 * keepalive 配置指令解析， 同时设置peer.init_upstream为ngx_http_upstream_init_keepalive
 * 
 * 支持upstream的长链接。如果不配置该指令，ngx和ups每次请求都会建立一个新的tcp连接，请求结束后关闭。
 * 
 * 设置最大的空闲连接数
 * 
 */
static char *
ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t            *uscf;
    ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    //如果已经赋值了，说明配置了重复指令
    if (kcf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    /* init upstream handler */

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    // 保存原回调函数， 和指令顺序有关系
    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    // 该模块嵌入执行的开始，该函数在ngx_http_upstream_init_main_conf函数中被调用。
    uscf->peer.init_upstream = ngx_http_upstream_init_keepalive;

    return NGX_CONF_OK;
}
