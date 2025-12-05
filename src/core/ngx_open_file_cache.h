
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_OPEN_FILE_CACHE_H_INCLUDED_
#define _NGX_OPEN_FILE_CACHE_H_INCLUDED_


#define NGX_OPEN_FILE_DIRECTIO_OFF  NGX_MAX_OFF_T_VALUE


/**
 * 表示一个打开的文件信息
 */
typedef struct {
    ngx_fd_t                 fd;                // 打开的文件描述符
    ngx_file_uniq_t          uniq;              // 打开的文件序列号
    time_t                   mtime;             // 最后修改时间
    off_t                    size;              // 文件大小
    off_t                    fs_size;           // 占用磁盘大小
    off_t                    directio;          // 和O_DIRECT有关，取决于directio指令。
    size_t                   read_ahead;

    ngx_err_t                err;               // errno
    char                    *failed;            // 发生错误的操作，如open openat等。

    time_t                   valid;             // 缓存有效时长

    ngx_uint_t               min_uses;           // 缓存个数

#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 test_dir:1;
    unsigned                 test_only:1;
    unsigned                 log:1;
    unsigned                 errors:1;      // 缓存错误的文件
    unsigned                 events:1;

    unsigned                 is_dir:1;      // 是否是目录
    unsigned                 is_file:1;     // 是否是文件
    unsigned                 is_link:1;     // 是否是链接文件
    unsigned                 is_exec:1;     // 可执行
    unsigned                 is_directio:1;
} ngx_open_file_info_t;


typedef struct ngx_cached_open_file_s  ngx_cached_open_file_t;

struct ngx_cached_open_file_s {
    ngx_rbtree_node_t        node;          // 用来添加到缓存红黑树
    ngx_queue_t              queue;         // 用来添加到双向队列

    u_char                  *name;          // 文件名
    time_t                   created;       // 创建时间
    time_t                   accessed;      // 访问时间

    ngx_fd_t                 fd;
    ngx_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    ngx_err_t                err;

    uint32_t                 uses;          // 被索引的次数，历史累加

#if (NGX_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 count:24;      // 缓存文件当前被引用数
    unsigned                 close:1;       // 是否关闭
    unsigned                 use_event:1;   // 是否使用事件驱动

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;

    ngx_event_t             *event;
};


/**
 * 代表一个文件打开缓存区
 * 
 * Defines a cache that stores the file descriptors of frequently used logs whose names contain variables
 */
typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;
    ngx_queue_t              expire_queue;

    ngx_uint_t               current;   // 缓存文件个数，rbtee节点个数。
    ngx_uint_t               max;       //缓冲区中最大文件描述符数量
    time_t                   inactive;  //默认10秒，超过该时间内文件没有被访问，将被关闭
} ngx_open_file_cache_t;


typedef struct {
    ngx_open_file_cache_t   *cache;
    ngx_cached_open_file_t  *file;
    ngx_uint_t               min_uses;
    ngx_log_t               *log;
} ngx_open_file_cache_cleanup_t;


typedef struct {

    /* ngx_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    ngx_event_t             *read;
    ngx_event_t             *write;
    ngx_fd_t                 fd;

    ngx_cached_open_file_t  *file;
    ngx_open_file_cache_t   *cache;
} ngx_open_file_cache_event_t;


ngx_open_file_cache_t *ngx_open_file_cache_init(ngx_pool_t *pool,
    ngx_uint_t max, time_t inactive);
ngx_int_t ngx_open_cached_file(ngx_open_file_cache_t *cache, ngx_str_t *name,
    ngx_open_file_info_t *of, ngx_pool_t *pool);


#endif /* _NGX_OPEN_FILE_CACHE_H_INCLUDED_ */
