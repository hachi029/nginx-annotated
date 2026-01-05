
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
typedef void (*ngx_event_notify_peer_pt)(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);
typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);


/**
 * https://nginx.org/en/docs/dev/development_guide.html#http_load_balancing
 * 
 * 表示与上游服务器的连接的结构体
 * Nginx会试图主动向其他上游服务器建立连接， 并以此连接与上游服务器通信
 * 是对 ngx_connection_t的封装，ngx_connection_t从连接池里获取，ngx_peer_connection_t 每次都会重新生成
 */
struct ngx_peer_connection_s {

    //一个主动连接实际上也需要 ngx_connection_t结构体中的大部分成员，并且出于重用的考虑而定义了 connection成员
    ngx_connection_t                *connection;

    //上游服务器的地址， 当负载均衡算法选定一台后端服务器时，把它的地址信息保存在pc->sockaddr、pc->socklen、pc->name。
    struct sockaddr                 *sockaddr;      // 上游服务器的 socket地址
    socklen_t                        socklen;       // sockaddr的长度
    ngx_str_t                       *name;          // 上游服务器的名称


    //表示在连接一个上游服务器时，当前连接出现异常失败后可以重试的次数，也就是对于一个请求，允许的最多失败次数
    ngx_uint_t                       tries;     //尝试次数
    //upstream启动时间
    ngx_msec_t                       start_time;

    //get(pc, data)
    //The method called when the upstream module is ready to pass a request to an upstream server and needs to know its address
    //The method has to fill the sockaddr, socklen, and name fields of ngx_peer_connection_t structure
    /**
     * The return is one of:
     * NGX_OK — Server was selected.
       NGX_ERROR — Internal error occurred.
       NGX_BUSY — no servers are currently available. This can happen due to many reasons, including: the dynamic server group is empty, 
                  all servers in the group are in the failed state, or all servers in the group are already handling the maximum number of connections.
       NGX_DONE — the underlying connection was reused and there is no need to create a new connection to the upstream server. 
                    This value is set by the keepalive module.
     */
    //获取连接的方法，如果使用长连接构成的连接池，那么必须要实现 get方法
    ngx_event_get_peer_pt            get;       /* 负载均衡模块实现，用于选取一个后端服务器 */
    //free(pc, data, state)
    //The method called when an upstream module has finished work with a particular server.
    //The state argument is the completion status of the upstream connection, a bitmask with the following possible values:
    /**
     *  NGX_PEER_FAILED — Attempt was unsuccessful
     *  NGX_PEER_NEXT — A special case when upstream server returns codes 403 or 404, which are not considered a failure.
     *  NGX_PEER_KEEPALIVE — Currently unused
     */
    // 与 get方法对应的释放连接的方法
    ngx_event_free_peer_pt           free;      /* 负载均衡模块实现，用于释放一个后端服务器 */

    ngx_event_notify_peer_pt         notify;
    //这个 data指针仅用于和上面的 get、 free方法配合传递参数，它的具体含义与实现 get方法、 free方法的模块相关，
    //可参照 ngx_event_get_peer_pt和 ngx_event_free_peer_pt方法原型中的 data参数
    /* 为每个请求专用的负载均衡数据，一般指向ngx_http_upstream_<name>_peer_data_t */
    void                            *data;  //get需要的数据

    /**
     * SSL-specific methods that enable caching sessions to upstream servers. 
     * The implementation is provided by the round-robin balancing method
     */
#if (NGX_SSL || NGX_COMPAT)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

    ngx_addr_t                      *local; // 本机地址信息

    int                              type;
    int                              rcvbuf;   // 套接字的接收缓冲区大小

    ngx_log_t                       *log;   // 记录日志的 ngx_log_t对象

    unsigned                         cached:1;  // 标志位，为 1时表示上面的 connection连接已经缓存
    unsigned                         transparent:1;
    unsigned                         so_keepalive:1;
    unsigned                         down:1;

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
