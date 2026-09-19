
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_kqueue_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_mirror_module;
extern ngx_module_t  ngx_http_try_files_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_conn_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_uwsgi_module;
extern ngx_module_t  ngx_http_scgi_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_hash_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_least_conn_module;
extern ngx_module_t  ngx_http_upstream_random_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_module_t  ngx_http_upstream_zone_module;
extern ngx_module_t  ngx_http_my_script_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

ngx_module_t *ngx_modules_bak[] = {
    &ngx_core_module,                   //core
    &ngx_errlog_module,                 //core
    &ngx_conf_module,                   //conf
    &ngx_regex_module,                  //core
    &ngx_events_module,                 //core
    &ngx_event_core_module,             //event
    &ngx_kqueue_module,                 //event
    &ngx_http_module,                   //core
    &ngx_http_core_module,              //http
    &ngx_http_log_module,               //http
    &ngx_http_upstream_module,          //http
    &ngx_http_static_module,
    &ngx_http_autoindex_module,
    &ngx_http_index_module,
    &ngx_http_mirror_module,
    &ngx_http_try_files_module,
    &ngx_http_auth_basic_module,
    &ngx_http_access_module,
    &ngx_http_limit_conn_module,
    &ngx_http_limit_req_module,
    &ngx_http_geo_module,
    &ngx_http_map_module,
    &ngx_http_split_clients_module,
    &ngx_http_referer_module,
    &ngx_http_rewrite_module,
    &ngx_http_proxy_module,
    &ngx_http_fastcgi_module,
    &ngx_http_uwsgi_module,
    &ngx_http_scgi_module,
    &ngx_http_memcached_module,
    &ngx_http_empty_gif_module,
    &ngx_http_browser_module,
    &ngx_http_upstream_hash_module,
    &ngx_http_upstream_ip_hash_module,
    &ngx_http_upstream_least_conn_module,
    &ngx_http_upstream_random_module,
    &ngx_http_upstream_keepalive_module,
    &ngx_http_upstream_zone_module,
    &ngx_http_my_script_module,
    &ngx_http_write_filter_module,            /* 最后一个body filter，负责往外发送数据 */
    //这个filter负责计算响应头的总大小，并分配内存，组装响应头，并调用ngx_http_write_filter发送。
    &ngx_http_header_filter_module,           /* 最后一个header filter，负责在内存中拼接出完整的http响应头，并调用ngx_http_write_filter发送 */
    &ngx_http_chunked_filter_module,          /* 对响应头中没有content_length头的请求，强制短连接（低于http 1.1）或采用chunked编码（http 1.1) */
    &ngx_http_range_header_filter_module,     /* header filter，负责处理range头 */
    &ngx_http_gzip_filter_module,             /* 支持流式的数据压缩 */
    &ngx_http_postpone_filter_module,         /* body filter，负责处理子请求和主请求数据的输出顺序 */
    &ngx_http_ssi_filter_module,              /* 支持过滤SSI请求，采用发起子请求的方式，去获取include进来的文件 */
    &ngx_http_charset_filter_module,            /* 支持添加charset，也支持将内容从一种字符集转换到另外一种字符集 */
    &ngx_http_userid_filter_module,             /* 支持添加统计用的识别用户的cookie */
    &ngx_http_headers_filter_module,            /* 支持设置expire和Cache-control头，支持添加任意名称的头 */
    /*第三方模块会被Nginx注册在ngx_http_copy_filter_module之后，ngx_http_headers_filter_module之前*/
    &ngx_http_copy_filter_module,               /* 根据需求重新复制输出链表中的某些节点比如将in_file的节点从文件读出并复制到新的节点），并交给后续filter进行处理 */
    &ngx_http_range_body_filter_module,         /* body filter，支持range功能，如果请求包含range请求，那就只发送range请求的一段内容 */
    /* 是第一个header_filter. ngx_http_top_header_filter指向的第一个filter */
    &ngx_http_not_modified_filter_module,       /* 如果请求的if-modified-since等于回复的last-modified值，说明回复没有变化，清空所有回复的内容，返回304 */
    NULL
};

