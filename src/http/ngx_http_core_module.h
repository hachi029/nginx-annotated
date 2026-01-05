
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#elif (NGX_COMPAT)
typedef struct ngx_thread_pool_s  ngx_thread_pool_t;
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define NGX_HTTP_SERVER_TOKENS_OFF      0
#define NGX_HTTP_SERVER_TOKENS_ON       1
#define NGX_HTTP_SERVER_TOKENS_BUILD    2


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


/**
 * 一条listen指令的解析结果
 * https://nginx.org/en/docs/http/ngx_http_core_module.html#listen
 */
typedef struct {
    //listen指令监听的地址，
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    //listen指令监听的地址， 文本格式
    ngx_str_t                  addr_text;

    //是否设置了监听选项，用来检查是否有相同address 的Listen同时配置了监听选项
    unsigned                   set:1;
    //标识是否是default_server
    unsigned                   default_server:1;
    //标识是否需要执行bind
    unsigned                   bind:1;
    //标识是否是通配符地址。如0.0.0.0 或 ::
    unsigned                   wildcard:1;
    //标识是否是ssl
    unsigned                   ssl:1;
    //标识是否是http2
    unsigned                   http2:1;
    //标识是否是quic
    unsigned                   quic:1;
#if (NGX_HAVE_INET6)
    //ipv6only=on|off
    unsigned                   ipv6only:1;
#endif
    //标识是否开启 TCP_DEFER_ACCEPT 选项
    unsigned                   deferred_accept:1;
    //标识是否开启 SO_REUSEPORT 选项
    unsigned                   reuseport:1;
    //1:on;2:off
    unsigned                   so_keepalive:2;
    //specifying that all connections accepted on this port should use the PROXY protocol.
    unsigned                   proxy_protocol:1;

    //backlog配置
    int                        backlog;
    //接收缓冲区大小
    int                        rcvbuf;
    int                        sndbuf;
    //SOCK_DGRAM
    int                        type;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    //enables “TCP Fast Open” for the listening socket (1.5.8) and limits the maximum length for the queue of 
    //connections that have not yet completed the three-way handshake.
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} ngx_http_listen_opt_t;


/**
 * NGX请求处理的11个阶段
 */
typedef enum {
    // 在接收到完整的 HTTP头部后处理的 HTTP阶段
    //First phase. The ngx_http_realip_module registers its handler at this phase to enable substitution of client addresses before any other module is invoked
    NGX_HTTP_POST_READ_PHASE = 0,

    //A subrequest starts in the NGX_HTTP_SERVER_REWRITE_PHASE phase. 
    //It passes through the same subsequent phases as a normal request and is assigned a location based on its own URI
    //在将请求的URI与 location表达式匹配前，修改请求的 URI（所谓的重定向）是一个独立的 HTTP阶段
    //server级别的uri重写阶段，也就是该阶段执行处于server块内，location块外的重写指令，在读取请求头的过程中nginx会根据host及端口找到对应的虚拟主机配置；
    //Phase where rewrite directives defined in a server block (but outside a location block) are processed. The ngx_http_rewrite_module installs its handler at this phase
    NGX_HTTP_SERVER_REWRITE_PHASE,

    //根据请求的 URI寻找匹配的 location表达式
    //寻找location配置阶段，该阶段使用重写之后的uri来查找对应的location, 该阶段可能会被执行多次，因为也可能有location级别的重写指令
    /**
     * Special phase where a location is chosen based on the request URI. 
     * Before this phase, the default location for the relevant virtual server is assigned to the request, 
     * and any module requesting a location configuration receives the configuration for the default server location. 
     * This phase assigns a new location to the request. No additional handlers can be registered at this phase
     */
    NGX_HTTP_FIND_CONFIG_PHASE,     //只能由ngx_http_core_module模块实现
    //在 NGX_HTTP_FIND_CONFIG_PHASE阶段寻找到匹配的 location之后再修改请求的 URI
    //location级别的uri重写阶段，该阶段执行location基本的重写指令，也可能会被执行多次
    // Same as NGX_HTTP_SERVER_REWRITE_PHASE, but for rewrite rules defined in the location, chosen in the previous phase.
    NGX_HTTP_REWRITE_PHASE,
    //这一阶段是用于在 rewrite重写 URL后，防止错误的 nginx.conf配置导致死循环（递归地修改 URI）
    //这一阶段仅由 ngx_http_core_module模块处理。目前，控制死循环的方式很简单，首先检查 rewrite的次数，
    //如果一个请求超过10次重定向 ,就认为进入了rewrite死循环，这时在 NGX_HTTP_POST_REWRITE_PHASE阶段就会向用户返回 500，表示服务器内部错误
    /**
     * Special phase where the request is redirected to a new location if its URI changed during a rewrite. 
     * This is implemented by the request going through the NGX_HTTP_FIND_CONFIG_PHASE again. 
     * No additional handlers can be registered at this phase
     */
    NGX_HTTP_POST_REWRITE_PHASE,  //仅由 ngx_http_core_module模块处理

    //处理 NGX_HTTP_ACCESS_PHASE阶段决定请求的访问权限前， HTTP模块可以介入的处理阶段
    /**
     * A common phase for different types of handlers, not associated with access control. 
     * The standard nginx modules ngx_http_limit_conn_module and ngx_http_limit_req_module register their handlers at this phase.
     */
    NGX_HTTP_PREACCESS_PHASE,

    /**
     * Phase where it is verified that the client is authorized to make the request
     * By default the client must pass the authorization check of all handlers registered at this phase for the request to continue to the next phase
     * The satisfy directive, can be used to permit processing to continue if any of the phase handlers authorizes the client
     * */ 
    //用于让HTTP模块判断是否允许这个请求访问 Nginx服务器
    NGX_HTTP_ACCESS_PHASE,
    //在 NGX_HTTP_ACCESS_PHASE阶段中，当 HTTP模块的 handler处理函数返回不允许访问的错误码时
    //（实际就是 NGX_HTTP_FORBIDDEN或者 NGX_HTTP_UNAUTHORIZED），这里将负责向用户发送拒绝服务的错误响应。
    //因此，这个阶段实际上用于给NGX_HTTP_ACCESS_PHASE阶段收尾
    /**
     * Special phase where the satisfy any directive is processed. 
     * If some access phase handlers denied access and none explicitly allowed it, the request is finalized. 
     * No additional handlers can be registered at this phase
     */
    NGX_HTTP_POST_ACCESS_PHASE,

    //Phase for handlers to be called prior to generating content
    //这个阶段完全是为 try_files配置项而设立的，当 HTTP请求访问静态文件资源时， 
    //try_files配置项可以使这个请求顺序地访问多个静态文件资源，如果某一次访问失败，
    //则继续访问 try_files中指定的下一个静态资源。这个功能完全是在 NGX_HTTP_TRY_FILES_PHASE阶段中实现的
    NGX_HTTP_PRECONTENT_PHASE,

    /**
     * Phase where the response is normally generated.
     * Multiple nginx standard modules register their handlers at this phase, including ngx_http_index_module or ngx_http_static_module. 
     * They are called sequentially until one of them produces the output. 
     * It's also possible to set content handlers on a per-location basis
     * If the ngx_http_core_module's location configuration has handler set, it is called as the content handler and the handlers installed at this phase are ignored
     */
    // 用于处理 HTTP请求内容的阶段，这是大部分 HTTP模块介入的阶段
    NGX_HTTP_CONTENT_PHASE,

    /**
     * Phase where request logging is performed. 
     * Currently, only the ngx_http_log_module registers its handler at this stage for access logging. 
     * Log phase handlers are called at the very end of request processing, right before freeing the request
     */
    //进入该阶段表明该请求的响应已经发送到系统发送缓冲区, 在ngx_http_free_request中执行。具体的执行的函数为ngx_http_log_request
    //处理完请求后记录日志的阶段。例如，ngx_http_log_module模块就在这个阶段中加入了一个 handler处理方法，
    //使得每个 HTTP请求处理完毕后会记录 access_log访问日志
    NGX_HTTP_LOG_PHASE
} ngx_http_phases;

//每个阶段的handler处理器
typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

//一个 HTTP处理阶段中的 checker检查方法，仅可以由 HTTP框架实现，以此控制 HTTP请求的处理流程
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

//ngx_http_phase_handler_t结构体仅表示处理阶段中的一个处理方法

//这4个checker方法的主要任务在于，根据phase_handler执行某个HTTP模块实现的回调方法，
//并根据方法的返回值决定：当前阶段已经完全结束了吗？下次要执行的回调方法是哪一个？
//究竟是立刻执行下一个回调方法还是先把控制权交还给epoll

/**
 * 在处理到某一个 HTTP阶段时， HTTP框架将会在 checker方法已实现的前提下首先调用 checker方法来处理请求，
 * 而不会直接调用任何阶段中的handler方法，只有在 checker方法中才会去调用 handler方法。
 * 因此，事实上所有的 checker方法都是由框架中的 ngx_http_core_module模块实现的，且普通的 HTTP模块无法重定义checker方法
 */
struct ngx_http_phase_handler_s {
    //在各个HTTP模块能 够介入的7个阶段中，实际上共享了4个checker方法：
    //ngx_http_core_generic_phase 、 ngx_http_core_rewrite_phase 、
    //ngx_http_core_access_phase 、 ngx_http_core_content_phase
    ngx_http_phase_handler_pt  checker;     //checker
    ngx_http_handler_pt        handler;     //HTTP模块实现的handler方法

    //将要执行的下一个 HTTP处理阶段的序号
    ngx_uint_t                 next;   //指向下一个阶段的phase_handler  r->phase_handler = ph->next;
};


//是所有ngx_http_phase_handler_t组成的数组
typedef struct {
    //handlers是由 ngx_http_phase_handler_s 构成的数组首地址，它表示一个请求可能经历的所有 ngx_http_handler_pt处理方法
    ngx_http_phase_handler_t  *handlers;        //数组，索引为r->phase_handler
    //表示 NGX_HTTP_SERVER_REWRITE_PHASE阶段第 1个 ngx_http_phase_handler_t 处理方法在handlers数组中的序号，
    //用于在执行HTTP请求的任何阶段中快速跳转到 NGX_HTTP_SERVER_REWRITE_PHASE阶段处理请求
    ngx_uint_t                 server_rewrite_index;
    //表示 NGX_HTTP_REWRITE_PHASE阶段第 1个 ngx_http_phase_handler_t 处理方法在handlers数组中的序号，
    //用于在执行 HTTP请求的任何阶段中快速跳转到NGX_HTTP_REWRITE_PHASE阶段处理请求
    ngx_uint_t                 location_rewrite_index;
} ngx_http_phase_engine_t;


/**
  ngx_http_core_main_conf_t {
       ...
      ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
   }
 */
typedef struct {
    //handlers动态数组保存着每一个 HTTP模块初始化时添加到当前阶段的处理方法
    //每个phase都会有一个handler数组
    ngx_array_t                handlers;    //元素类型为 ngx_http_handler_pt 的函数
} ngx_http_phase_t;


/**
 * ngx_http_core_module在main级别的配置结构
 * 表示http{}块配置，只有一个全局唯一的实例
 */
typedef struct {
    /**
     * 动态数组，每一个代表一个server{}块的配置
     * 存储指针的动态数组，每个指针指向ngx_http_core_srv_conf_t结构体的地址，其成员类型为ngx_http_core_srv_conf_t**
     */
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    //phase_handler数组
    //由下面各阶段处理方法构成的 phases数组构建的阶段引擎才是流水式处理 HTTP请求的实际数据结构
    ngx_http_phase_engine_t    phase_engine;

    //ngx_http_headers_in 构成的hash表
    //其初始化流程参考  ngx_http_init_headers_in_hash 
    ngx_hash_t                 headers_in_hash;

    /**
     * 存储变量名的散列表，调用 ngx_http_get_variable 方法获取未索引的变量值时就靠这个
     * 散列表找到变量的解析方法
     */
    ngx_hash_t                 variables_hash;      //!!!!!!! 1.存放hash变量， 参考ngx_http_get_variable方法

    /**
     *  存储索引过的变量的数组，通常各模块使用变量时都会在 Nginx启动阶段从该数组中获得索引号， 
     *  这样，在Nginx运行期内，如果变量值没有被缓存，就会通过索引号在variables数组中找到变量的定义，再解析出变量值
     * 
     * variables/prefix_variables: 在配置解析阶段，会调用ngx_http_variables_init_vars()
     * 将所有模块定义的变量放入这两个动态数组里
     * 
     * 每个请求结构体r也有个和variables相同大小的表示变量值的variables字段
     * 
     * 与r->variables 一一对应
     */
    ngx_array_t                variables;         /* ngx_http_variable_t */     //!!!!!!! 2.存放索引变量
    //存放带有前缀的变量，如(http_、arg_)
    ngx_array_t                prefix_variables;  /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    /* 配置指令值 散列桶bucket最大数量 */
    ngx_uint_t                 server_names_hash_max_size;
    /* 配置指令值 每个散列桶bucket占用内存的最大值 */
    ngx_uint_t                 server_names_hash_bucket_size;

    //variables_hash_max_size 配置指令值
    ngx_uint_t                 variables_hash_max_size;
    //variables_hash_bucket_size 配置指令值
    ngx_uint_t                 variables_hash_bucket_size;

    // 用于构造 variables_hash散列表的初始结构体, 只是临时使用， 参考函数 ngx_http_variables_init_vars. 使用结束后置为NULL
    //时ngx构造散列表必需的数据结构
    ngx_hash_keys_arrays_t    *variables_keys;


    //存放着该 http{}配置块下监听的所有 ngx_http_conf_port_t端口。参考ngx_http_add_listen方法
    ngx_array_t               *ports;

    //用于在 HTTP框架初始化时帮助各个 HTTP模块在任意阶段中添加HTTP处理方法，
    //它是一个有 11个成员的 ngx_http_phase_t数组，其中每一个ngx_http_phase_t结构体对应一个 HTTP阶段。
    //在 HTTP框架初始化完毕后，运行过程中的 phases数组是无用的
    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];
} ngx_http_core_main_conf_t;


/**
 * ngx_http_core_module 在server级别配置结构体
 * 代表server{}配置
 * 
 * ngx_http_core_main_conf_t->ngx_http_conf_port_t->ngx_http_conf_addr_t->ngx_http_core_srv_conf_t
 * cmcf->ports->addrs->servers
 * 
 * ngx_http_find_virtual_server()方法就是根据Host查找的这个结构
 */
typedef struct {
    //表示该server{}配置块下配置的多个server_name指令
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    // 指向当前 server块所属的 ngx_http_conf_ctx_t结构体
    ngx_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    ngx_uint_t                  line;

    //当前 server块的虚拟主机名，如果存在的话，则会与HTTP请求中的Host头部做匹配，
    //匹配上后再由当前 ngx_http_core_srv_conf_t处理请求
    ngx_str_t                   server_name;

    //connection_pool_size 配置指令值, 默认为512
    size_t                      connection_pool_size;
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#request_pool_size
    //创建ngx_http_request_t时，为r分配的pool初始大小
    size_t                      request_pool_size;
    //client_header_buffer_size 配置指令值, 默认为1k
    size_t                      client_header_buffer_size;

    //large_client_header_buffers 配置指令值, 默认为 4 8k
    ngx_bufs_t                  large_client_header_buffers;

    //client_header_timeout 配置指令值, 默认为60s 
    ngx_msec_t                  client_header_timeout;

    //ignore_invalid_headers 配置指令值
    ngx_flag_t                  ignore_invalid_headers;
    //merge_slashes  配置指令值
    ngx_flag_t                  merge_slashes;
    //underscores_in_headers 配置指令值
    ngx_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (NGX_PCRE)
    //server_name 是否配置了正则表达式，且包含捕获组
    unsigned                    captures:1;
#endif

    //named_locations @xxx
    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


/**
 * 表示一条server_name配置指令
 */
typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;     //编译出的正则
#endif
    //指向的server{}配置结构体
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;    // server_name配置指令的第一个参数
} ngx_http_server_name_t;


/**
 * 代表一个虚拟主机名称
 */
typedef struct {
    //支持简单通配符的散列表
    ngx_hash_combined_t        names;

    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

    //listen指令是否配置了ssl
    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   quic:1;
    //当前连接是否启用了 proxy_protocol
    unsigned                   proxy_protocol:1;
};


/**
 * 一个监听地址
 */
typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


/**
 * 代表一个监听端口
 */
typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    //该监听端口下的多个地址 ngx_http_in_addr_t
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


/**
 * 数据结构：
 * ngx_http_conf_port_t->ngx_http_conf_addr_t->ngx_http_core_srv_conf_t
 * port(80)->addr(127.0.0.1)->server(aa.com)
 *     |                |->server(bb.com)
 *     |->addr(192.168.23.11)->server(cc.com)
 *                          |->server(dd.com)
 * 
 * listen指令 每监听一个TCP端口，都将使用一个独立的ngx_http_conf_port_t结构体来表示
 */
typedef struct {
    ngx_int_t                  family;  // socket地址家族
    ngx_int_t                  type;    // 标识是TCP或是UDP
    in_port_t                  port;    // 监听端
    //监听的端口下对应着的所有 ngx_http_conf_addr_t地址. 
    //同一个端口，可以监听不同地址，如127.0.0.1:8000、173.39.160.51:8000
    ngx_array_t                addrs;     /* array of ngx_http_conf_addr_t */
} ngx_http_conf_port_t;


/**
 * 一个端口下可能有多个地址监听。 参考ngx_http_conf_port_t下的addrs属性
 * 
 * 代表一个监听地址 127.0.0.1:8000
 * 
 * 
 * ngx_http_conf_port_t->ngx_http_conf_addr_t->ngx_http_core_srv_conf_t
 * port(80)->addr(127.0.0.1)->server(aa.com)
       |                |->server(bb.com)
       |->addr(192.168.23.11)->server(cc.com)
                            |->server(dd.com)
 */
typedef struct {
    //多个相同的addr指向同一个ngx_http_listen_opt_t结构。多条listen指令，如果addr相同，则只能有一条指令配置监听选项，其他addr仅指向该指令的监听选项结构体
    ngx_http_listen_opt_t      opt; // 监听套接字的各种属性， 一条listen指令的解析结果。

    unsigned                   protocols:3;
    unsigned                   protocols_set:1;
    unsigned                   protocols_changed:1;

    //*以下 3个散列表用于加速寻找到对应监听端口上的新连接，确定到底使用哪个 server{}虚拟主机下的配置来处理它。
    //所以，散列表的值就是 ngx_http_core_srv_conf_t 结构体的地址
    ngx_hash_t                 hash;    // 1.1完全匹配 server name的散列表
    ngx_hash_wildcard_t       *wc_head; // 1.2通配符前置的散列表
    ngx_hash_wildcard_t       *wc_tail; // 1.3通配符后置的散列表

#if (NGX_PCRE)
    // 下面的 regex数组中元素的个数
    ngx_uint_t                 nregex;
    //指向静态数组，其数组成员就是 ngx_http_server_name_t结构体
    ngx_http_server_name_t    *regex;   //2 表示正则表达式及其匹配的 server{}虚拟主机
#endif

    /* the default server configuration for this address:port */
    // 该监听端口下对应的默认 server{}虚拟主机
    ngx_http_core_srv_conf_t  *default_server;
    // servers动态数组中的成员将指向 ngx_http_core_srv_conf_t结构体(表示一个server{}配置块)
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


/**
 * 代表一条error_page配置指令
 * 一条error_page配置指令 配置了响应码及其对于的url。 url可以包含变量
 */
typedef struct {
    ngx_int_t                  status;      //响应码
    ngx_int_t                  overwrite;
    ngx_http_complex_value_t   value;       //包含变量的url
    ngx_str_t                  args;
} ngx_http_err_page_t;


/**
 * ngx_http_core_module 在location级别配置结构体
 * 代表一个location{}的配置
 * ngx_http_core_loc_conf_t拥有足够的信息来表达1个location块，
 * 它的loc_conf成员也可以引用到各HTTP模块在当前location块中的配置项
 */
struct ngx_http_core_loc_conf_s {
    // location的名字 如 "/"、"/index.html"、"/images/"等
    // location的名称，即 nginx.conf中 location后的表达式
    ngx_str_t     name;          /* location name */
    ngx_str_t     escaped_name;

#if (NGX_PCRE)
    /* 正则引擎编译过的 正则表达式对象 */
    ngx_http_regex_t  *regex;
#endif

    // if () {}
    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    //location @xxx 路径以@开头
    unsigned      named:1;

    // = 表示精确匹配，如果找匹配到，立即停止搜索并立即处理此请求
    unsigned      exact_match:1;
    //表示不再执行正则匹配,  ^= 修饰符
    unsigned      noregex:1;

    // name以 / 结尾
    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    //location的静态二叉查找树
    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    //location为正则表达式的匹配
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    //指向所属 location块内 ngx_http_conf_ctx_t结构体中的 loc_conf指针数组，
    //它保存着当前location块内所有HTTP模块create_loc_conf方法产生的结构体指针
    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    //content_handler
    ngx_http_handler_pt  handler;       //即独特的content_handler注册方式

    /* location name length for inclusive location with inherited alias */

    /**
     *  alias所在location 中 ，location name的length
     *  如果没配置alias, 则为0
     * location /i/ {
            alias /data/w3/images/;
        }
        /i/ 的长度
     */
    size_t        alias;                    // name.length
    //root为root指令配置的文件路径。默认为$prefix/html
    ngx_str_t     root;                    /* root, alias */
    //post_action 配置指令值
    ngx_str_t     post_action;

    //当root或alias 配置项里包含变量， root_lengths和root_values 会被用到
    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    //default_type 配置指令值
    ngx_str_t     default_type;

    //client_max_body_size 配置指令值
    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    //directio_alignment 配置指令值
    off_t         directio_alignment;      /* directio_alignment */

    //client_body_buffer_size 配置指令值
    //设置缓存请求体的buffer大小，默认为系统页大小的2倍，当请求体的大小超过此大小时，nginx会把请求体写入到临时文件中。
    //可以根据业务需求设置合适的大小，尽量避免磁盘io操作;
    size_t        client_body_buffer_size; /* client_body_buffer_size */
    //send_lowat 配置指令值
    size_t        send_lowat;              /* send_lowat */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#postpone_output
    //直到有postpone_output大小的数据，才将数据输出
    size_t        postpone_output;         /* postpone_output */
    //sendfile_max_chunk 配置指令值
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    //read_ahead 配置指令解析
    size_t        read_ahead;              /* read_ahead */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#subrequest_output_buffer_size
    //subrequest_output_buffer_size 配置指令值， 默认为4k，Sets the size of the buffer used for storing the response body of a subrequest
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    //limit_rate 配置指令值
    ngx_http_complex_value_t  *limit_rate; /* limit_rate */
    //limit_rate_after 配置指令值
    ngx_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    //client_body_timeout 配置指令值
    ngx_msec_t    client_body_timeout;     /* client_body_timeout */
    //send_timeout 配置指令值
    ngx_msec_t    send_timeout;            /* send_timeout */
    //keepalive_time 配置指令值
    ngx_msec_t    keepalive_time;          /* keepalive_time */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */
    //keepalive_min_timeout 配置指令值
    ngx_msec_t    keepalive_min_timeout;   /* keepalive_min_timeout */
    //lingering_time 配置指令值
    ngx_msec_t    lingering_time;          /* lingering_time */
    //lingering_timeout 配置指令值
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    //resolver_timeout 配置指令值
    ngx_msec_t    resolver_timeout;        /* resolver_timeout */
    //auth_delay 配置指令值
    ngx_msec_t    auth_delay;              /* auth_delay */

    //动态域名解析器，用于运行时dns解析。 是根据resolver配置指令创建的
    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    //keepalive_requests 配置指令值
    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    //keepalive_disable 配置指令值
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    //satisfy 配置指令值
    ngx_uint_t    satisfy;                 /* satisfy */
    //lingering_close 配置指令值
    ngx_uint_t    lingering_close;         /* lingering_close */
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#if_modified_since
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    //max_ranges 配置指令值
    ngx_uint_t    max_ranges;              /* max_ranges */
    //client_body_in_file_only 配置指令值  https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_in_file_only
    //设置是否总是将请求体保存在临时文件中，默认为off
    //当此指定被设置为on时，即使客户端显式指示了请求体长度为0时，nginx还是会为请求创建一个临时文件。
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    //client_body_in_single_buffer 配置指令值
    //指示是否将请求体完整的存储在一块连续的内存中，默认为off，
    //如果此指令被设置为on，则nginx会保证请求体在不大于client_body_buffer_size设置的值时，被存放在一块连续的内存中，
    //但超过大小时会被整个写入一个临时文件;
    ngx_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    ngx_flag_t    internal;                /* internal */
    //sendfile 配置指令值
    ngx_flag_t    sendfile;                /* sendfile */
    ngx_flag_t    aio;                     /* aio */
    //aio_write 配置指令值
    ngx_flag_t    aio_write;               /* aio_write */
    //tcp_nopush 配置指令值
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    //tcp_nodelay 配置指令值
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    //reset_timedout_connection 配置指令值
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    //absolute_redirect 配置指令值
    ngx_flag_t    absolute_redirect;       /* absolute_redirect */
    //server_name_in_redirect 配置指令值
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    //port_in_redirect 配置指令值
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    //msie_padding 配置指令值
    ngx_flag_t    msie_padding;            /* msie_padding */
    //msie_refresh 配置指令值
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    //log_not_found 配置指令值
    ngx_flag_t    log_not_found;           /* log_not_found */
    //log_subrequest 配置指令值
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    //recursive_error_pages 配置指令值
    //https://nginx.org/en/docs/http/ngx_http_core_module.html#recursive_error_pages
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    //server_tokens 配置指令值
    ngx_uint_t    server_tokens;           /* server_tokens */
    //chunked_transfer_encoding on | off; https://nginx.org/en/docs/http/ngx_http_core_module.html#chunked_transfer_encoding
    //Allows disabling chunked transfer encoding in HTTP/1.1
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    //etag 配置指令值
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    /**
     * 在 HTTP 协议中，Vary 响应头用于告知缓存机制（如浏览器缓存、CDN 或代理服务器），在判断是否直接使用缓存内容时，
     * 需要考虑哪些请求头的变化。它的作用是确保缓存的响应内容能够正确匹配后续请求的上下文环境（如不同语言、编码格式等），
     * 避免因缓存 “一刀切” 导致的内容不匹配问题
     */
    //https://nginx.org/en/docs/http/ngx_http_gzip_module.html#gzip_vary
    //Enables or disables inserting the “Vary: Accept-Encoding” response header field if the directives gzip, gzip_static, or gunzip are active.
    //该指令用于设定是否相应数据包添加Vary：Accept-Enconding HTTP头（header）。需要注意的而是，由于bug的原因，如果设置添加该头，会导致IE4~6不缓存内容
    ngx_flag_t    gzip_vary;               /* gzip_vary */

    //支持gzip的最小http版本
    ngx_uint_t    gzip_http_version;       /* gzip_http_version */
    //配置指令 https://nginx.org/en/docs/http/ngx_http_gzip_module.html#gzip_proxied
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    //https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page
    //error_pages 配置指令， 元素类型 ngx_http_err_page_t。 配置了遇到指定的status时，应该重定向的url。配合intercept_errors机制
    ngx_array_t  *error_pages;             /* error_page */

    //client_body_temp_path 配置指令值
    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */

    //open_file_cache 配置指令值
    ngx_open_file_cache_t  *open_file_cache;
    //open_file_cache_valid  配置指令值, 打开文件多长时间内有效
    //Sets a time after which open_file_cache elements should be validated.
    time_t        open_file_cache_valid;
    //open_file_cache_min_uses 配置指令值
    ngx_uint_t    open_file_cache_min_uses;
    //open_file_cache_errors 配置指令值
    ngx_flag_t    open_file_cache_errors;
    //open_file_cache_events 配置指令值
    ngx_flag_t    open_file_cache_events;

    ngx_log_t    *error_log;

    //types_hash_max_size 配置指令值
    ngx_uint_t    types_hash_max_size;
    //types_hash_bucket_size 配置指令值
    ngx_uint_t    types_hash_bucket_size;

    //将同一个server块内多个表达location块的 ngx_http_core_loc_conf_t结构体以双向链表方式组织起来，
    //该 locations 指针将指向 ngx_http_location_queue_t结构体
    //属于当前块的所有ocation块通过ngx_http_location_queue_t结构体构成的双向链表
    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


/**
 * 每一个ngx_http_core_loc_conf_t结构体(代表一个location{}块)都对应着 1个ngx_http_location_queue_t，
 * 因此，此处将把ngx_http_location_queue_t串联成双向链表
 */
typedef struct {
    //queue将作为 ngx_queue_t双向链表容器，从而将 ngx_http_location_queue_t结构体连接起来
    ngx_queue_t                      queue;
    //如果 location中的字符串可以精确匹配（包括正则表达式），exact将指向对应的 ngx_http_core_loc_conf_t结构体，否则值为 NULL
    ngx_http_core_loc_conf_t        *exact;
    //如果 location中的字符串无法精确匹配（包括了自定义的通配符）， inclusive将指向对应的 ngx_http_core_loc_conf_t结构体，否则值为 NULL
    ngx_http_core_loc_conf_t        *inclusive;
    //指向 location的名称
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


/**
 * location查找的静态二叉树节点
 * 
 * 最终存储location的结构体，将location以树状组织在一起，实现location的快速查找
 * 
 * http://blog.chinaunix.net/uid-27767798-id-3759557.html
 * 
 */
struct ngx_http_location_tree_node_s {
    //left指向的node是比parent的节点小的
    ngx_http_location_tree_node_t   *left;  // 左子树
    //right指向的node是比parent节点大的
    ngx_http_location_tree_node_t   *right;  // 右子树
    //tree指向拥有parent前缀的节点
    ngx_http_location_tree_node_t   *tree;  // 无法完全匹配的 location 组成的树

    //如果 location对应的 URI匹配字符串属于能够完全匹配的类型，则 exact指向其对应的 ngx_http_core_loc_conf_t结构体，否则为 NULL空指针
    ngx_http_core_loc_conf_t        *exact;
    //如果 location对应的 URI匹配字符串属于无法完全匹配的类型，则 inclusive指向其对应的 ngx_http_core_loc_conf_t结构体，否则为 NULL空指针
    ngx_http_core_loc_conf_t        *inclusive;

    // name字符串的实际长度
    u_short                          len;
    // 自动重定向标志
    u_char                           auto_redirect;
    // name指向 location对应的 URI匹配表达式
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


// 创建子请求对象，复制父请求的大部分字段
ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


// 当http请求结束时的清理动作
ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


// 响应头过滤函数原型
typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);

// 响应体过滤函数原型，chain 是本次要发送的数据
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);

// 请求体过滤函数原型, chain 是接收到的数据
typedef ngx_int_t (*ngx_http_request_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_table_elt_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);

ngx_int_t ngx_http_link_multi_headers(ngx_http_request_t *r);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


/**
 * 移除content_length响应头
 * 1.content_length_n 设置为-1
 * 2.content_length响应头置空
 */
#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

/**
 * 移除accept_ranges响应头
 * 1. allow_ranges设置为0
 * 2. accept_ranges响应头置空
 */
#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

/**
 * 移除last_modified响应头
 * 1. last_modified_time设置为-1
 * 2. last_modified响应头置空
 */
#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

/**
 * 移除location响应头
 */
#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

/**
 * 移除etag响应头
 */
#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
