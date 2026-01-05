
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_in_memory(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


/**
 * https://nginx.org/en/docs/dev/development_guide.html#http_subrequests
 * 
 * The output header in a subrequest is always ignored. 
 * The ngx_http_postpone_filter places the subrequest's output body in the right position relative to other data produced by the parent request.
 * 
 * Subrequests are related to the concept of active requests. 
 * A request r is considered active if c->data == r, where c is the client connection object. 
 * At any given point, only the active request in a request group is allowed to output its buffers to the client. 
 * An inactive request can still send its output to the filter chain, but it does not pass beyond the ngx_http_postpone_filter 
 * and remains buffered by that filter until the request becomes active. Here are some rules of request activation:
 *  1.Initially, the main request is active.
 *  2.The first subrequest of an active request becomes active right after creation.
 *  3.The ngx_http_postpone_filter activates the next request in the active request's subrequest list, once all data prior to that request are sent.
 *  4.When a request is finalized, its parent is activated.
 * 
 * Subrequests are normally created in a body filter, in which case their output can be treated like the output from any explicit request. 
 * This means that eventually the output of a subrequest is sent to the client, 
 * after all explicit buffers that are passed before subrequest creation and before any buffers that are passed after creation. 
 * This ordering is preserved even for large hierarchies of subrequests. 
 * 
 */
/**
 * 是一个必选filter, 不能通过编译选项移除。实现子请求必不可少, 用来将子请求和主请求的输出链合并
 * 
 * 将子请求产生的数据按序放回父请求
 * 
 * 为了subrequest功能而建立的
 * 如果原始请求派生出许多子请求，并且希望将所有子请求的响应依次转发给客户端，
 * 当然，这里的“依次”就是按照创建子请求的顺序来发送响应，这时，postpone模块就有了“用武之地”
 * 
 * 
 * 此模块会强制地把待转发的响应包体放在一个链表中发送，只有优先转发的子请求结束后才会开始转发下一个子请求中的响应
 * 
 * 此模块注册一个 body_filter ngx_http_postpone_filter
 */
ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


/**
 * 
 * 用来缓存住父request，这里的缓存就是将需要发送的数据保存到一个链表中。
 * 这个是因为会先执行subrequest，然后才会执行request，因此如果有subrequest的话，这个filter就会跳过后面的发送filter，直接返回ok
 * 
 * body_filter, 是保证子请求顺序正确的关键，通过c->data控制 子请求数据发送的顺序
 * 
 * 每当使用ngx_http_output_filter方法（反向代理模块也使用该方法转发响应）向下游的客户端发送响应包体时，
 * 都会调用到ngx_http_postpone_filter_module过滤模块处理这段要发送的包体
 * 
 * in就是将要发送给客户端的一段包体
 */
static ngx_int_t
ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_connection_t              *c;
    ngx_http_postponed_request_t  *pr;

      // c是 Nginx与下游客户端间的连接， c->data保存的是原始请求
    c = r->connection;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    //不转发响应到客户端
    if (r->subrequest_in_memory) {
        //将子请求的响应in拷贝到r->out中. r->out缓冲区大小不能超过配置指令的值
        return ngx_http_postpone_filter_in_memory(r, in);
    }

    // 如果当前请求r是一个子请求（因为 c->data指向原始请求）
    // 当前请求不能往out chain发送数据，如果产生了数据，新建一个节点，将它保存在当前请求的postponed队尾。这样就保证了数据按序发到客户端 */
    if (r != c->data) {

        //如果待发送的in包体不为空，则把in加到postponed链表中属于当前请求的ngx_http_postponed_request_t结构体的out链表中，
        //同时返回NGX_OK，这意味着本次不会把in包体发给客户端
        if (in) {
            //保存数据
            if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
                return NGX_ERROR;
            }
            //不再继续让后续body_filter处理。实际上后续的body_filter都是官方提供的filter模块
            return NGX_OK;
        }
    // 如果当前请求是子请求，而 in包体又为空，那么直接返回即可
#if 0
        /* TODO: SSI may pass NULL */
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return NGX_OK;
    }

/* 到这里，表示当前请求可以往out chain发送数据，如果它的postponed链表中没有子请求，也没有数据，
       则直接发送当前产生的数据in或者继续发送out chain中之前没有发送完成的数据 */

    // 如果postponed为空，表示请求r没有子请求产生的响应需要转发
    //r->postponed是一个链表，链表每个节点缓存了一个子请求的响应  
    if (r->postponed == NULL) {

        if (in || c->buffered) {
            //直接调用下一个HTTP过滤模块继续处理in包体即可。如果没有错误的话，就会开始向下游客户端发送响应
            return ngx_http_next_body_filter(r->main, in);
        }

        /* 当前请求没有需要发送的数据 */
        return NGX_OK;
    }

    /* 当前请求的postponed链表中之前就存在需要处理的节点，则新建一个节点，保存当前产生的数据in，并将它插入到postponed队尾 */
    //至此，说明postponed链表中是有子请求产生的响应需要转发的，可以先把in包体加到待转发响应的末尾
    if (in) {
        //先把in包体加到待转发响应的末尾
        if (ngx_http_postpone_filter_add(r, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    // 循环处理 postponed 链表中所有子请求待转发的包体
    do {
        pr = r->postponed;

        /* 如果该节点保存的是一个子请求，则将它加到主请求的posted_requests链表中，以便下次调用ngx_http_run_posted_requests函数，处理该子节点 */
        if (pr->request) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            //r->postponed指向下一个节点
            r->postponed = pr->next;

            /* 按照后序遍历产生的序列，因为当前请求（节点）有未处理的子请求(节点)，必须先处理完该子请求，才能继续处理后面的子节点。
               这里将该子请求设置为可以往out chain发送数据的请求。  */
            c->data = pr->request;

            /* 将该子请求加入主请求的posted_requests链表 */
            return ngx_http_post_request(pr->request, NULL);
        }

        /* 如果该节点保存的是数据，可以直接处理该节点，将它发送到out chain */
        // 调用下一个 HTTP过滤模块转发 out链表中保存的待转发的包体
        if (pr->out == NULL) {
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            //说明pr->out不为空，此时需要将保存的父request的数据发送。
            if (ngx_http_next_body_filter(r->main, pr->out) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
        //遍历完 postponed链表
        r->postponed = pr->next;

    } while (r->postponed);

    return NGX_OK;
}


/**
 * 将in封装成一个ngx_http_postponed_request_t结构体，然后加入到r->postponed链表尾部
 */
static ngx_int_t
ngx_http_postpone_filter_add(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_postponed_request_t  *pr, **ppr;

    //ppr指向r->postponed最后一个节点
    if (r->postponed) {
        //找到r->postponed链表最后一个节点
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
    }

    //如果ppr指向的指针为null, 则申请新的ngx_http_postponed_request_t结构体
    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    //将in复制到pr->out尾部,也就是保存request 需要发送的数据。
    if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


/**
 * 当子请求数据在内存中的处理，确保子请求响应数据的有序性
 *  if (r->subrequest_in_memory) {
        return ngx_http_postpone_filter_in_memory(r, in);
    }
 * 
 * 当子请求运行结束后，响应头数据就在r->out里
 * 
 * 将子请求的响应in拷贝到r->out中. r->out缓冲区大小不能超过配置指令的值 subrequest_output_buffer_size
 */
static ngx_int_t
ngx_http_postpone_filter_in_memory(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     len;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter in memory");

    if (r->out == NULL) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        //确定len，为之后创建缓冲区r->out的大小
        if (r->headers_out.content_length_n != -1) {
            //如果headers_out.content_length_n 有值，则使用此值
            len = r->headers_out.content_length_n;

            //subrequest_output_buffer_size 为配置指令值，设置用于存储子请求响应的缓冲区大小，默认为4k或8k
            if (len > clcf->subrequest_output_buffer_size) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "too big subrequest response: %uz", len);
                return NGX_ERROR;
            }

        } else {
            //如果没有content_length响应头，则使用配置指令的值
            len = clcf->subrequest_output_buffer_size;
        }

        //创建缓冲区
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last_buf = 1;                        //只用一块内存保存数据

        r->out = ngx_alloc_chain_link(r->pool); //分配链表节点
        if (r->out == NULL) {
            return NGX_ERROR;
        }

        r->out->buf = b;                    //连接到缓冲区
        r->out->next = NULL;                //链表结束，即只有一个节点
    }

    b = r->out->buf;

    //遍历in数据链表拷贝
    for ( /* void */ ; in; in = in->next) {

        if (ngx_buf_special(in->buf)) {         //跳过特殊的控制用的缓冲区
            continue;
        }

        len = in->buf->last - in->buf->pos;     //检测缓冲区数据长度

        //如果子请求响应超过了r->out的大小，直接返回错误
        if (len > (size_t) (b->end - b->last)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "too big subrequest response");
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http postpone filter in memory %uz bytes", len);

        //将子请求响应拷贝到缓冲区r->out
        b->last = ngx_cpymem(b->last, in->buf->pos, len);
        in->buf->pos = in->buf->last;
    }

    return NGX_OK;
}


/**
 * postconfiguration
 * 安装一个body_filter
 */
static ngx_int_t
ngx_http_postpone_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
