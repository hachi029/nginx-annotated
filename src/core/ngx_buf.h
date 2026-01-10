
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/**
 * https://nginx.org/en/docs/dev/development_guide.html#buffer
 * 
 * it's used to hold data to be written to a destination or read from a source
 * 处理大数据的关键数据结构，它既应用于内存数据也应用于磁盘数据
 * 包含以下各个域:
 *  start, end — 为缓冲区分配内存块的边界。
 *  pos, last — 内存缓冲的边界，通常在start和end的范围内。
 *  file_pos, file_last — 文件缓冲区的边界，从文件开头表示为偏移。
 *  tag — 用于区分缓冲区，由不同的nginx模块创建，通常是为了缓冲区重用。
 *  file — 文件对象。
 *  temporary — 标识表明缓冲区引用可写内存。
 *  memory — 标识缓冲区可读。
 * 
 */
struct ngx_buf_s {
    ///*pos通常是用来告诉使用者本次应该从 pos这个位置开始处理内存中的数据，
    //这样设置是因为同一个ngx_buf_t可能被多次反复处理。当然， pos的含义是由使用它的模块定义的
    u_char          *pos;       //未消费的数据的首个地址
    //last通常表示有效的内容到此为止，注意，pos与last之间的内存是希望nginx处理的内容
    u_char          *last;      //未消费的数据的末尾地址
    //当数据位于文件中时
    off_t            file_pos;  //处理文件时，待处理的文件开始标记
    off_t            file_last; //处理文件时，待处理的文件结尾标记

    //如果ngx_buf_t缓冲区用于内存，那么start指向这段内存的起始地址
    u_char          *start;         /* start of buffer */
     //如果ngx_buf_t缓冲区用于内存，那么end指向这段内存的结束地址
    u_char          *end;           /* end of buffer */
    //Unique value used to distinguish buffers; created by different nginx modules, usually for the purpose of buffer reuse.
    //表示当前缓冲区的类型，例如由哪个模块使用就指向这个模块 ngx_module_t变量的地址
    ngx_buf_tag_t    tag;
    // 引用的文件
    ngx_file_t      *file;
    /**
     * shadow — Reference to another ("shadow") buffer related to the current buffer, 
     * usually in the sense that the buffer uses data from the shadow. 
     * When the buffer is consumed, the shadow buffer is normally also marked as consumed.
     */
    /* 当前缓冲区的一个影子缓冲区，即当一个缓冲区引自于另一个缓冲区的数据，就会发生相互指向对方的shadow指针
     * 将现在的buffer关联到另外一个（“shadow”）buffer，通常数据使用“shadow”buffer 中的数据， 当buffer使用完毕，后“shadow”buffer 也一并释放。
     */
    ngx_buf_t       *shadow;


    // 临时内存标志位，为 1时表示数据在内存中且这段内存可以修改
    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    // 标志位，为 1时表示数据在内存中且这段内存不可以被修改。 大部分情况下不可改，因为很多ngx_buf_t只是引用其他buf。相对于temporary
    unsigned         memory:1;

    // 标志位，为 1时表示这段内存是用mmap系统调用映射过来的，不可以被修改
    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;

    //Flag indicating that the buffer can be reused and needs to be consumed as soon as possible
    // 标志位，为 1时表示可回收， 标识可以重复使用缓冲区，并且需要尽快消耗。
    unsigned         recycled:1;

    // 标志位，为1时表示这段缓冲区处理的是文件而不是内存
    unsigned         in_file:1;
    //标识缓冲区所有数据需要进行输出。 Flag indicating that all data prior to the buffer need to be flushed
    unsigned         flush:1;   // 标志位，为 1时表示需要执行 flush操作

    //Flag indicating that the buffer carries no data or special signal like flush or last_buf. 
    //By default nginx considers such buffers an error condition, but this flag tells nginx to skip the error check.
    /**
     * 标志位，对于操作这块缓冲区时是否使用同步方式，需谨慎考虑，这可能会阻塞Nginx进程，
     * Nginx中所有操作几乎都是异步的，这是它支持高并发的关键。
     * 有些框架代码在 sync为 1时可能会有阻塞的方式进行 I/O操作，它的意义视使用它的 Nginx模块而定
     */
    unsigned         sync:1;

    /**
     * Flag indicating that the buffer is the last in output.
     * 标志位，表示是否是最后一块缓冲区，因为 ngx_buf_t可以由ngx_chain_t链表串联起来，
     * 因此，当 last_buf为 1时，表示当前是最后一块待处理的缓冲区
     */
    unsigned         last_buf:1;    
    //Flag indicating that there are no more data buffers in a request or subrequest.
    //标志位，表示是否是 ngx_chain_t中的最后一块缓冲区。
    //标识表明请求request或子请求subrequest中没有更多的数据缓冲区
    unsigned         last_in_chain:1;

    unsigned         last_shadow:1;     /* 标志位，为1时，表示是否是最后一个影子缓冲区 */
    unsigned         temp_file:1;       // 标志位，表示当前缓冲区是否属于临时文件

    /* STUB */ int   num;
};


/**
 * ngx_chain_t是与ngx_buf_t配合使用的链表数据结构
 * 一个链表节点
 */
struct ngx_chain_s {
    ngx_buf_t    *buf;      //指向当前的ngx_buf_t缓冲区
    ngx_chain_t  *next;     //指向下一个ngx_chain_t, 如果这是最后一个 ngx_chain_t，则需要把next置为NULL，否则会导致未定义错误
};


/**
 * 
 * 代表一个缓冲区的大小配置，包括缓冲区的个数和每个缓冲区的大小
 * 
 * 如 gunzip_buffers number size;
 */
typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

//定义了向下游发送响应的方式，是对nginx_chain_t的封装，它包含了三种类型的chain，分别是in，free以及busy
//参考 ngx_output_chain 函数
struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;               /*  这个域也就是拷贝数据的地方，一般输出的话都是从in直接copy相应的size到buf中 */
    ngx_chain_t                 *in;                /* 保存了将要发送的chain */
    ngx_chain_t                 *free;              /* 保存了一些空的buf，也就是说如果free存在，都会直接从free中取buf到前面的buf域 */
    ngx_chain_t                 *busy;              /* 保存了还未发送的chain */

    unsigned                     sendfile:1;        /* sendfile标记 */
    unsigned                     directio:1;         /* directio标记 */
    unsigned                     unaligned:1;
    /* 是否需要在内存中重新复制一份(使用sendfile的话， 内存中没有文件的拷贝的，而我们有时需要处理文件，此时就需要设置这个标记) */  
    unsigned                     need_in_memory:1;
    /* 是否需要在内存中重新复制一份，不管buf是在内存还是文件,这样的话，后续模块可以直接修改这块内存 */
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ///每次从pool中重新alloc一个buf这个值都会相应加一
    ngx_int_t                    allocated; /* 已经分配的buf个数 */
    ngx_bufs_t                   bufs;      /* 对应loc conf中设置的bufs */
    /* 这个用来标记当前那个模块使用这个chain */
    ngx_buf_tag_t                tag;       //ngx_buf_tag_t 为 void*, 一般为模块的地址

    //是一个回调函数，一般是ngx_http_next_filter, 也就是继续调用filter链
    ngx_output_chain_filter_pt   output_filter;
    //对于ngx_http_copy_filter为当前请求r
    void                        *filter_ctx;    /* 当前filter的上下文，这里是由于upstream也会调用output_chain */
};


//主要用于ustream
typedef struct {
    //保存了所要输出的chain
    ngx_chain_t                 *out;
    //保存了这次新加入的所需要输出的chain
    ngx_chain_t                **last;
    //表示当前连接
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

//返回b上未消费的数据长度   
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

//创建一个缓冲区。需要传入pool和buf的大小
ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
//申请内存放置ngx_buf_t结构体
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
/**
 * 回收chain, 只是将其放入pool->chain链表中，没有对buf字段进行处理
 */
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
