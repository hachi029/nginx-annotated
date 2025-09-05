
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static char *ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_init_phases(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_headers_in_hash(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);
static ngx_int_t ngx_http_init_phase_handlers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf);

static ngx_int_t ngx_http_add_addresses(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_address(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_port_t *port,
    ngx_http_listen_opt_t *lsopt);
static ngx_int_t ngx_http_add_server(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_conf_addr_t *addr);

static char *ngx_http_merge_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static char *ngx_http_merge_locations(ngx_conf_t *cf,
    ngx_queue_t *locations, void **loc_conf, ngx_http_module_t *module,
    ngx_uint_t ctx_index);
static ngx_int_t ngx_http_init_locations(ngx_conf_t *cf,
    ngx_http_core_srv_conf_t *cscf, ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf);
static ngx_int_t ngx_http_escape_location_name(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *clcf);
static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one,
    const ngx_queue_t *two);
static ngx_int_t ngx_http_join_exact_locations(ngx_conf_t *cf,
    ngx_queue_t *locations);
static void ngx_http_create_locations_list(ngx_queue_t *locations,
    ngx_queue_t *q);
static ngx_http_location_tree_node_t *
    ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix);

static ngx_int_t ngx_http_optimize_servers(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_http_server_names(ngx_conf_t *cf,
    ngx_http_core_main_conf_t *cmcf, ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_cmp_conf_addrs(const void *one, const void *two);
static int ngx_libc_cdecl ngx_http_cmp_dns_wildcards(const void *one,
    const void *two);

static ngx_int_t ngx_http_init_listening(ngx_conf_t *cf,
    ngx_http_conf_port_t *port);
static ngx_listening_t *ngx_http_add_listening(ngx_conf_t *cf,
    ngx_http_conf_addr_t *addr);
static ngx_int_t ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr);
#endif

ngx_uint_t   ngx_http_max_module;

/**
 * 响应体过滤链表的顺序
 * +--------------------------+
  |ngx_http_range_body_filter|
  +----------+---------------+
             v
  +----------+---------+
  |ngx_http_copy_filter|
  +----------+---------+
             v
  +----------+-----------------+
  |ngx_http_charset_body_filter|
  +----------+-----------------+
             v
  +----------+-------------+
  |ngx_http_ssi_body_filter|
  +----------+-------------+
             v
  +----------+-------------+
  |ngx_http_postpone_filter|
  +----------+-------------+
             v
  +----------+--------------+
  |ngx_http_gzip_body_filter|
  +----------+--------------+
             v
  +----------+-----------------+
  |ngx_http_chunked_body_filter|
  +----------+-----------------+
             v
  +---------------------+
  |ngx_http_write_filter|
  +---------------------+
 */


/**
 * 响应头过滤链表的顺序:
 *+----------------------------+
  |ngx_http_not_modified_filter|
  +----------+-----------------+
             v
  +----------+------------+
  |ngx_http_headers_filter|
  +----------+------------+
             v
  +----------+-----------+
  |ngx_http_userid_filter|
  +----------+-----------+
             v
  +----------+-------------------+
  |ngx_http_charset_header_filter|
  +----------+-------------------+
             v
  +----------+---------------+
  |ngx_http_ssi_header_filter|
  +----------+---------------+
             v
  +----------+----------------+
  |ngx_http_gzip_header_filter|
  +----------+----------------+
             v
  +----------+-----------------+
  |ngx_http_range_header_filter|
  +----------+-----------------+
             v
  +----------+-------------------+
  |ngx_http_chunked_header_filter|
  +----------+-------------------+
             v
  +----------+-----------+
  |ngx_http_header_filter|
  +----------------------+

  除了最后一个模块是真正发送响应头部给客户端之外，其他模块都只是对响应头部进行修改

  ngx_http_header_filter_module，提供的处理方法ngx_http_header_filter 根据请求结构体ngx_http_request_t 中的 header_out 成员序列化字符流，
  并发送序列化之后的响应头部
 */

/**
 * 使用方法
 * ngx_http_next_header_filter = ngx_http_top_header_filter; 
 * ngx_http_top_header_filter = ngx_http_myfilter_header_filter; 
 * ngx_http_next_body_filter = ngx_http_top_body_filter; 
 * ngx_http_top_body_filter = ngx_http_myfilter_body_filter;
 *
 */

// 过滤链表头指针，过滤header
// 每个过滤模块都需要内部实现一个函数指针，链接为单向链表
// 在modules数组里位置在前的是链表末尾，后面的是链表前面
// 链表的最后一个模块是ngx_http_header_filter_module
ngx_http_output_header_filter_pt  ngx_http_top_header_filter;   //ngx_http_header_filter, 最后调用的也是 ngx_http_write_filter

// 过滤链表头指针，过滤body
// 每个过滤模块都需要内部实现一个函数指针，链接为单向链表
// 在modules数组里位置在前的是链表末尾，后面的是链表前面
// 链表的最后一个模块是ngx_http_write_filter_module
ngx_http_output_body_filter_pt    ngx_http_top_body_filter;     // ngx_http_write_filter

// 过滤链表头指针，过滤请求body，1.8.x新增，通常只有一个 ngx_http_request_body_save_filter
ngx_http_request_body_filter_pt   ngx_http_top_request_body_filter;

// http请求的默认类型，数组最后用空字符串表示结束
ngx_str_t  ngx_http_html_default_types[] = {
    ngx_string("text/html"),
    ngx_null_string
};

//http模块也只有一个指令，定义http{}配置块
static ngx_command_t  ngx_http_commands[] = {

    { ngx_string("http"),
      // 出现在main域，配置块，无参数  
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      // 解析http{}配置块，里面有server{}/location{}等
      ngx_http_block,
      0,
      0,
      NULL },

      ngx_null_command
};


// 没有create/init函数，只有出现http指令才创建配置结构体
static ngx_core_module_t  ngx_http_module_ctx = {
    ngx_string("http"),                     /* module name */
    NULL,                                   /* create_conf */
    NULL                                    /* init_conf */
};


/**
 * ngx_http_module， 是一个核心模块，定义了http模块
 */
ngx_module_t  ngx_http_module = {
    NGX_MODULE_V1,
    &ngx_http_module_ctx,                  /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
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
 * http 配置指令解析，当遇到http{}时调用此方法，为HTTP模块初始化的入口函数
 * 
 *  1.Nginx 进程进入主循环，在主循环中调用配置解析器解析配置文件nginx.conf;
 *  2.在配置文件中遇到 http{} 块配置，则 HTTP 框架开始初始化并启动，其由函数 ngx_http_block() 实现；
 *  3.HTTP 框架初始化所有 HTTP 模块的序列号，并创建 3 个类型为 ngx_http_conf_ctx_t 结构的数组用于存储所有HTTP 模块的create_main_conf、create_srv_conf、create_loc_conf方法返回的指针地址；
 *  4.调用每个 HTTP 模块的 preconfiguration 方法；
 *  5.HTTP 框架调用函数 ngx_conf_parse() 开始循环解析配置文件 *nginx.conf *中的http{}块里面的所有配置项；
 *  6.HTTP 框架处理完毕 http{} 配置项，根据解析配置项的结果，必要时进行配置项合并处理；
 *  7.继续处理其他 http{} 块之外的配置项，直到配置文件解析器处理完所有配置项后通知Nginx 主循环配置项解析完毕。此时，Nginx 才会启动Web 服务器；
 * 
 * HTTP 框架解析完毕 http{} 块配置项时，会根据解析的结果进行合并配置项操作，即合并 http{}、server{}、location{} 不同块下各HTTP 模块生成的存放配置项的结构体。其合并过程如下所示：
 * 
 *  1.若 HTTP 模块实现了 merge_srv_conf 方法，则将 http{} 块下create_srv_conf 生成的结构体与遍历每一个 server{}配置块下的结构体进行merge_srv_conf 操作；
 *  2.若 HTTP 模块实现了 merge_loc_conf 方法，则将 http{} 块下create_loc_conf 生成的结构体与嵌套每一个server{} 配置块下的结构体进行merge_loc_conf 操作；
 *  3.若 HTTP 模块实现了 merge_loc_conf 方法，则将server{} 块下create_loc_conf 生成的结构体与嵌套每一个location{}配置块下的结构体进行merge_loc_conf 操作；
 *  4.若 HTTP 模块实现了 merge_loc_conf 方法，则将location{} 块下create_loc_conf 生成的结构体与嵌套每一个location{}配置块下的结构体进行merge_loc_conf 操作；
*/
static char *
ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   mi, m, s;
    ngx_conf_t                   pcf;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t         *ctx;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (*(ngx_http_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    //创建ngx_http_conf_ctx_t结构体。 ngx_http_conf_ctx_t存储了所有http模块分别在main/src/loc级别的配置
    /* the main http context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * conf 是结构体ngx_cycle_t 成员conf_ctx数组中的元素，
     * 该元素conf指向ngx_http_module模块所对应的配置项结构信息；
     */
    *(ngx_http_conf_ctx_t **) conf = ctx;


    /* count the number of the http modules and set up their indices */

    /* 初始化所有HTTP模块的ctx_index序号，并计算所有http模块的数量 */
    ngx_http_max_module = ngx_count_modules(cf->cycle, NGX_HTTP_MODULE);


    /* 分别生成 3 个数组存储所有的 HTTP 模块的 create_main_conf、create_srv_conf、create_loc_conf 方法返回的地址 */
    /* the http main_conf context, it is the same in the all http contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_http_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

     /*
     * 分配存储HTTP模块main级别下的srv_conf配置项的空间；
     */
    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the http null loc_conf context, it is used to merge
     * the server{}s' loc_conf's
     */

     /*
     * 分配存储HTTP模块main级别下的loc_conf配置项的空间；
     */
    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all http modules
     */

    //遍历每个NGX_HTTP_MODULE，调用其 create_main_conf/create_srv_conf/create_loc_conf方法
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        //对于http_module, 其ctx为 ngx_http_module_t
        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        //调用每个HTTP模块实现的create_main_conf方法
        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        //调用每个HTTP模块实现的create_srv_conf方法
        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        //调用每个HTTP模块实现的create_loc_conf方法
        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /*
     * 保存待解析配置项结构cf的副本为pcf，待解析完毕后恢复cf；
     * 这里备份是由于配置指令解析函数ngx_conf_parse递归调用，因此为了不影响外层的调用环境；
     */
    pcf = *cf;

    /*
     * 把HTTP模块解析指令的上下文参数保存到配置项结构ngx_http_conf_ctx_t ctx中；
     *   将解析配置的上下文切换成刚刚建立的ctx
     */
    cf->ctx = ctx;  /* 值-结果 模式 */

    //遍历每个NGX_HTTP_MODULE，调用每个模块的preconfiguration方法
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        //调用每个HTTP模块的preconfiguration方法
        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /*
     * 调用模块通用配置项解析函数ngx_conf_parse解析http{}块内的指令；
     */
    /* parse inside the http{} block */

    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;
    /*
     * 开始解析http{}块内的指令；这里必须注意的是：http{}块内可能会包含server{}块，
     * 而server{}可能会包含location{}块，location{}块会嵌套location{}块；
     * 还需注意的是http{}块内可能有多个server{}块，location{}块也可能有多个location{}块；
     * 因此，配置项解析函数ngx_conf_parse是被递归调用的；
     * */
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        goto failed;
    }

   /*
     * 解析完成http{}块内的所有指令后（包括server{}、location{}块的解析），
     * 进行下面的程序
     */
    /*
     * init http{} main_conf's, merge the server{}s' srv_conf's
     * and its location{}s' loc_conf's
     */

     //cmcf是全局唯一的代表http{}块的配置结构
    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    /* 获取所有srv_conf配置项结构 */
    cscfp = cmcf->servers.elts;

     /*
     * 遍历所有HTTP模块，并初始化每个HTTP模块的main_conf结构（调用每个模块的init_main_conf()方法），
     * 同时合并srv_conf 结构（当然srv_conf结构里面包含loc_conf结构，所有也合并loc_conf结构）；
     */
    for (m = 0; cf->cycle->modules[m]; m++) {
        //跳过非HTTP模块
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        //ngx_http_module_t
        //ngx_modules[m]是一个 ngx_module_t模块结构体，它的 ctx成员对于 HTTP模块来说是 ngx_http_module_t接口
        module = cf->cycle->modules[m]->ctx;
        //ctx_index是这个HTTP模块在所有 HTTP模块中的序号
        mi = cf->cycle->modules[m]->ctx_index;

        /* init http{} main_conf's */

        //调用每个模块的init_main_conf方法, 初始化HTTP模块的main_conf结构
        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        /* 合并当前HTTP模块不同级别的配置项结构 */
        // 调用 ngx_http_merge_servers方法合并 ngx_modules[m]模块
        rv = ngx_http_merge_servers(cf, cmcf, module, mi);
        if (rv != NGX_CONF_OK) {
            goto failed;
        }
    }

    /* 以下是监听端口管理的内容 */

    /* create location trees */

    //遍历http{}块下的所有server{}块, 构建由location块构造的静态二叉平衡查找树
    for (s = 0; s < cmcf->servers.nelts; s++) {

        // 获取server{}块下location{}块所对应的ngx_http_core_loc_conf_t loc_conf结构体
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        /*
         * 将ngx_http_core_loc_conf_t 组成的双向链表按照location匹配字符串进行排序；
         * 注意：location{}块可能嵌套location{}块，所以该函数是递归调用；
         */
        if (ngx_http_init_locations(cf, cscfp[s], clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        /*
         * 按照已排序的location{}的双向链表构建静态的二叉查找树，树根节点付给pclcf->static_locations
         * 该方法也是递归调用；
         * 
         */
        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    //在调用HTTP模块的 postconfiguration方法向这7个阶段中添加处理方法前，
    //需要先将phases数组中这7个阶段里的 handlers动态数组初始化（ngx_array_t类型需要执行ngx_array_init方法初始化），
    //在这一步骤 中，通过调用ngx_http_init_phases方法来初始化这8个动态数组
    if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    //初始化 cmcf->headers_in_hash hash表， 用于请求头处理的快速解析（根据请求头key， 查找其处理函数， 参考 ngx_http_headers_in ）
    if (ngx_http_init_headers_in_hash(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    //遍历每个NGX_HTTP_MODULE, 调用所有HTTP模块的postconfiguration方法
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        //调用每个模块的postconfiguration方法
        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    //核心变量初始化
    if (ngx_http_variables_init_vars(cf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * http{}'s cf->ctx was needed while the configuration merging
     * and in postconfiguration process
     */

    *cf = pcf;


    /* 初始化phase_engine_handlers数组 */
    if (ngx_http_init_phase_handlers(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }


    /* optimize the lists of ports, addresses and server names */

    //初始化listen 端口号 ip地址 服务器等监听信息
    /* 设置server与监听端口的关系，并设置新连接事件的处理方法 */
    if (ngx_http_optimize_servers(cf, cmcf, cmcf->ports) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

failed:

    *cf = pcf;

    return rv;
}


/**
 * ngx_http_block->.
 * 
 * 初始化11个阶段中8个支持挂载自定义handler的handlers动态数组ngx_array_t
 */
static ngx_int_t
ngx_http_init_phases(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    //NGX_HTTP_POST_READ_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_SERVER_REWRITE_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_REWRITE_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_PREACCESS_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_ACCESS_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_PRECONTENT_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers,
                       cf->pool, 2, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_CONTENT_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers,
                       cf->pool, 4, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //NGX_HTTP_LOG_PHASE
    if (ngx_array_init(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(ngx_http_handler_pt))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * 初始化hash表ngx_hash_t cmcf->headers_in_hash， 加速hash查找
 * 
 * 将数组 ngx_http_headers_in 构造为hash表 cmcf->headers_in_hash
 * 
 */
static ngx_int_t
ngx_http_init_headers_in_hash(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_array_t         headers_in;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    ngx_http_header_t  *header;

    //1. 构造用于初始化hash表的结构体 headers_in
    /**
     * headers_in 初始有32个ngx_hash_key_t元素
     */
    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    //计算hash值（将请求头key转小写，然后计算hash）
    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    //构造hash初始化参数 ngx_hash_init_t hash
    hash.hash = &cmcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    //2. 初始化hash表 &cmcf->headers_in_hash
    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * ngx_http_block->.
 * 
 * 和建立执行链相关的数据结构都保存在http主配置中，一个是phases字段，另外一个是phase_engine字段。其中phases字段为一个数组，
 * 它的元素个数等于阶段数目，即每个元素对应一个阶段。而phases数组的每个元素又是动态数组（ngx_array_t），
 * 每次模块注册处理函数时只需要在对应阶段的动态数组增加一个元素用来保存处理函数的指针。由于在某些执行阶段可能需要向后，或者向前跳转，
 * 简单的使用2个数组并不方便，所以nginx又组织了一个执行链，保存在了phase_engine字段，其每个节点包含一个next域用来保存跳跃目的节点的索引，
 * 而执行链的建立则在nginx初始化的post config阶段之后调用ngx_http_init_phase_handlers函数完成，
 */
static ngx_int_t
ngx_http_init_phase_handlers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf)
{
    ngx_int_t                   j;
    ngx_uint_t                  i, n;
    ngx_uint_t                  find_config_index, use_rewrite, use_access;
    ngx_http_handler_pt        *h;
    //最终的handler数组
    ngx_http_phase_handler_t   *ph;
    ngx_http_phase_handler_pt   checker;

    cmcf->phase_engine.server_rewrite_index = (ngx_uint_t) -1;
    cmcf->phase_engine.location_rewrite_index = (ngx_uint_t) -1;
    find_config_index = 0;
    //是否有使用rewrite以及access。
    use_rewrite = cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers.nelts ? 1 : 0;
    use_access = cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers.nelts ? 1 : 0;

    //开始计算handler 数组的大小
    n = 1                  /* find config phase */
        + use_rewrite      /* post rewrite phase */
        + use_access;      /* post access phase */

    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    //数组分配内存
    ph = ngx_pcalloc(cf->pool,
                     n * sizeof(ngx_http_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return NGX_ERROR;
    }

    //handler数组放到handlers里面。
    cmcf->phase_engine.handlers = ph;
    n = 0;

    //cmcf->phases 数组中保存了在post config之前注册的所有模块函数
    for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
        //取出对应的handler处理函数
        h = cmcf->phases[i].handlers.elts;

        //根据不同的phase来处理
        switch (i) {

            //server重写phase（也就是内部重定向phase)
        case NGX_HTTP_SERVER_REWRITE_PHASE:
            //如果有定义重写规则则设置重写handler的索引n.
            if (cmcf->phase_engine.server_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.server_rewrite_index = n;
            }
            //赋值checker
            checker = ngx_http_core_rewrite_phase;

            break;

        //find_config phase只有一个.
        case NGX_HTTP_FIND_CONFIG_PHASE:
            //这里设置 find_config_index，是因为当rewrite之后的url就必须重新挂载location的一些结构，因此就需要再次进入这个phase
            find_config_index = n;

            ph->checker = ngx_http_core_find_config_phase;
            n++;
            ph++;

            continue;

        case NGX_HTTP_REWRITE_PHASE:
            if (cmcf->phase_engine.location_rewrite_index == (ngx_uint_t) -1) {
                cmcf->phase_engine.location_rewrite_index = n;
            }
            checker = ngx_http_core_rewrite_phase;

            break;

        case NGX_HTTP_POST_REWRITE_PHASE:
            //如果有使用rewrite则给它的checker赋值
            if (use_rewrite) {
                ph->checker = ngx_http_core_post_rewrite_phase;
                //注意它的next就是find_config phase,也就是说需要重新挂载location的数据。
                ph->next = find_config_index;
                n++;
                ph++;
            }

            continue;

        case NGX_HTTP_ACCESS_PHASE:
            checker = ngx_http_core_access_phase;
            n++;
            break;

        case NGX_HTTP_POST_ACCESS_PHASE:
            if (use_access) {
                ph->checker = ngx_http_core_post_access_phase;
                ph->next = n;
                ph++;
            }

            continue;

        case NGX_HTTP_CONTENT_PHASE:
            checker = ngx_http_core_content_phase;
            break;

        default:
            checker = ngx_http_core_generic_phase;
        }

        //这里n刚好就是下一个phase的起始索引
        n += cmcf->phases[i].handlers.nelts;

        //开始遍历当前的phase的handler。
        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            //每个的handler就是注册的时候的回掉函数
            ph->handler = h[j];
            //next为下一个phase的索引
            ph->next = n;
            //下一个handler
            ph++;
        }
    }

    return NGX_OK;
}

/**
 * 合并配置项
HTTP 框架解析完毕 http{} 块配置项时，会根据解析的结果进行合并配置项操作，即合并 http{}、server{}、location{} 不同级别下各 HTTP 模块生成的存放配置项的结构体。其合并过程在文件src/http/ngx_http.c中定义，如下所示：

若 HTTP 模块实现了 merge_srv_conf 方法，则将 http{} 块下由 create_srv_conf 生成的 main 级别结构体与遍历每一个 server{}块下由 create_srv_conf生成的srv 级别的配置项结构体进行 merge_srv_conf 操作；
若 HTTP 模块实现了 merge_loc_conf 方法，则将 http{} 块下由 create_loc_conf 生成的 main 级别的配置项结构体与嵌套在每一个server{} 块下由 create_loc_conf 生成的srv级别的配置项结构体进行merge_loc_conf 操作；
若 HTTP 模块实现了 merge_loc_conf 方法，由于在上一步骤已经将main、srv级别由create_loc_conf 生成的结构体进行合并，只要把上一步骤合并的结果在 server{} 块下与嵌套每一个location{}块下由create_loc_conf 生成的配置项结构体再次进行merge_loc_conf 操作；
若 HTTP 模块实现了 merge_loc_conf 方法，则将上一步骤的合并结果与与嵌套每一个location{}块下由 create_loc_conf 生成的的配置项结构体再次进行merge_loc_conf 操作；
 */

/**
 *  合并了server相关的配置项，它同时也会合并location 相关的配置项，
 * cf 指向一个配置项
 * 
 */
static char *
ngx_http_merge_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                        *rv;
    ngx_uint_t                   s;
    ngx_http_conf_ctx_t         *ctx, saved;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;

    //从 ngx_http_core_main_conf_t的 servers动态数组中可以获取所有的 ngx_http_core_srv_conf_t结构体
    cscfp = cmcf->servers.elts;
    //注意，这个 ctx是在 http{}块下的全局 ngx_http_conf_ctx_t结构体
    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = NGX_CONF_OK;

    //遍历所有的server{}块下对应的 ngx_http_core_srv_conf_t结构体
    for (s = 0; s < cmcf->servers.nelts; s++) {

        /* merge the server{}s' srv_conf's */

        //srv_conf将指向所有的 HTTP模块产生的 server相关的 srv级别配置结构体
        ctx->srv_conf = cscfp[s]->ctx->srv_conf;

        // 如果当前 HTTP模块实现了 merge_srv_conf，则再调用合并方法
         /*
         * 若定义了merge_srv_conf 方法；
         * 则进行http{}块下create_srv_conf 生成的结构体与遍历server{}块配置项生成的结构体进行merge_srv_conf操作；
         */
         /*
         * 这里合并http{}块下main、server{}块下srv级别与server相关的配置项结构；
         *
         * 若定义了merge_srv_conf 方法；
         * 则将当前HTTP模块在http{}块下由create_srv_conf 生成的结构体
         * 与遍历每个server{}块由create_srv_conf生成的配置项结构体进行merge_srv_conf合并操作；
         * saved.srv_conf[ctx_index]表示当前HTTP模块在http{}块下由create_srv_conf方法创建的结构体；
         * cscfp[s]->ctx->srv_conf[ctx_index]表示当前HTTP模块在server{}块下由create_srv_conf方法创建的结构体；
         */
        if (module->merge_srv_conf) {
            //注意，在这里合并配置项时， saved.srv_conf[ctx_index]参数是当前 HTTP模块在 http{}块下由 create_srv_conf方法创建的结构体，
            //而 cscfp[s]->ctx->srv_conf[ctx_index]参数则是在server{}块下由 create_srv_conf方法创建的结构体
            rv = module->merge_srv_conf(cf, saved.srv_conf[ctx_index],
                                        cscfp[s]->ctx->srv_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        /*
         * 若定义了merge_loc_conf 方法；
         * 则进行http{}块下create_loc_conf 生成的结构体与嵌套server{}块配置项生成的结构体进行merge_loc_conf操作；
         */
        // 如果当前 HTTP模块实现了merge_loc_conf，则再调用合并方法
        /*
         * 这里合并http{}块下main、server{}块下srv级别与location相关的配置项结构；
         *
         * 若定义了merge_loc_conf 方法；
         * 则将当前HTTP模块在http{}块下由create_loc_conf 生成的结构体
         * 与嵌套在server{}块内由create_loc_conf生成的配置项结构体进行merge_loc_conf合并操作；
         *
         * 其中saved.loc_conf[ctx_index]表示当前HTTP模块在http{}块下由create_loc_conf方法生成的配置项结构体；
         * cscfp[s]->ctx->loc_conf[ctx_index]表示当前HTTP模块在server{}块下由create_loc_conf方法创建的配置项结构体；
         */
        if (module->merge_loc_conf) {

            /* merge the server{}'s loc_conf */

            //cscfp[s]->ctx->loc_conf这个动态数组中的成员都是由 server{}块下所有 HTTP模块的 create_loc_conf方法创建的结构体指针
            ctx->loc_conf = cscfp[s]->ctx->loc_conf;

            //首先将 http{}块下 main级别与 server{}块下 srv级别的location相关的结构体合并
            rv = module->merge_loc_conf(cf, saved.loc_conf[ctx_index],
                                        cscfp[s]->ctx->loc_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }

            /*
             * 若定义了merge_loc_conf 方法；
             * 则进行server{}块下create_loc_conf 生成的结构体与嵌套location{}块配置项生成的结构体进行merge_loc_conf操作；
             */

            /* merge the locations{}' loc_conf's */
            //server块下 ngx_http_core_module模块使用 create_loc_conf方法产生的 ngx_http_core_loc_conf_t结构体，
            //在 10.2.3节中曾经说过，它的locations成员将以双向链表的形式关联到所有当前 server{}块下的 location块
            clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

            //调用ngx_http_merge_locations方法，将 server{}块与其所包含的 location{}块下的结构体进行合并
            rv = ngx_http_merge_locations(cf, clcf->locations,
                                          cscfp[s]->ctx->loc_conf,
                                          module, ctx_index);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}


/**
 * 负责合并location相关的配置项
 */
static char *
ngx_http_merge_locations(ngx_conf_t *cf, ngx_queue_t *locations,
    void **loc_conf, ngx_http_module_t *module, ngx_uint_t ctx_index)
{
    char                       *rv;
    ngx_queue_t                *q;
    ngx_http_conf_ctx_t        *ctx, saved;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    //如果 locations链表为空，也就是说，当前 server块下没有 location块，则立刻返回
    if (locations == NULL) {
        return NGX_CONF_OK;
    }

    ctx = (ngx_http_conf_ctx_t *) cf->ctx;
    saved = *ctx;

    /*
     * 若定义了merge_loc_conf 方法；
     * 则进行location{}块下create_loc_conf 生成的结构体与嵌套location{}块配置项生成的结构体进行merge_loc_conf操作；
     */
    //遍历 locations双向链表
    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        //如果 location后的匹配字符串不依靠 Nginx自定义的通配符就可以完全匹配的话，
        //则 exact指向当前 location对应的 ngx_http_core_loc_conf_t结构体，否则使用inclusive指向该结构体，且 exact的优先级高于 inclusive
        clcf = lq->exact ? lq->exact : lq->inclusive;
        //clcf->loc_conf这个指针数组里保存着当前location下所有 HTTP模块使用 create_loc_conf方法生成的结构体的指针
        ctx->loc_conf = clcf->loc_conf;

        // 调用 merge_loc_conf方法合并 srv、 loc级别配置项
        rv = module->merge_loc_conf(cf, loc_conf[ctx_index],
                                    clcf->loc_conf[ctx_index]);
        if (rv != NGX_CONF_OK) {
            return rv;
        }

         /*
         * 递归调用该函数；
         * 因为location{}继续内嵌location{}
         */
        //因为 location{}中可以继续嵌套 location{}配置块，所以是可以继续合并的
        rv = ngx_http_merge_locations(cf, clcf->locations, clcf->loc_conf,
                                      module, ctx_index);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
    }

    *ctx = saved;

    return NGX_CONF_OK;
}


/*
* 将ngx_http_core_loc_conf_t 组成的双向链表按照location匹配字符串进行排序；
* 注意：location{}块可能嵌套location{}块，所以该函数是递归调用；
*/
static ngx_int_t
ngx_http_init_locations(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_uint_t                   n;
    ngx_queue_t                 *q, *locations, *named, tail;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_location_queue_t   *lq;
    ngx_http_core_loc_conf_t   **clcfp;
#if (NGX_PCRE)
    ngx_uint_t                   r;
    ngx_queue_t                 *regex;
#endif

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    //对server下的所有location进行排序，
    //exact(sorted) -> inclusive(sorted) -> regex -> named -> noname
    //排序结果：字母顺序（精确匹配、前缀匹配的）升序（有相同前缀的字符串，长的排在后面）｜正则匹配｜@匹配的｜if location的
    ngx_queue_sort(locations, ngx_http_cmp_locations);

    named = NULL;
    n = 0;
#if (NGX_PCRE)
    regex = NULL;
    r = 0;
#endif

    //遍历排序后的location。把@符号的location设置到cscf->named_locations。将nonamed类型的location设置到nonamed_locations。
    //正则的设置到pclcf->regex_locations上。最终locations只剩下了精确匹配的和前缀匹配的了。
    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        //递归调用
        if (ngx_http_init_locations(cf, NULL, clcf) != NGX_OK) {
            return NGX_ERROR;
        }

#if (NGX_PCRE)

        //如果是正则
        if (clcf->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }

#endif

        //如果是@符号的location
        if (clcf->named) {
            n++;

            if (named == NULL) {
                named = q;
            }

            continue;
        }

        //如果是location 内部嵌套的location
        if (clcf->noname) {
            break;
        }
    }

    /**精准匹配或前缀匹配*/

    if (q != ngx_queue_sentinel(locations)) {
        ngx_queue_split(locations, q, &tail);
    }

    if (named) {
        clcfp = ngx_palloc(cf->pool,
                           (n + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        cscf->named_locations = clcfp;

        for (q = named;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, named, &tail);
    }

#if (NGX_PCRE)

    if (regex) {

        clcfp = ngx_palloc(cf->pool,
                           (r + 1) * sizeof(ngx_http_core_loc_conf_t *));
        if (clcfp == NULL) {
            return NGX_ERROR;
        }

        pclcf->regex_locations = clcfp;

        for (q = regex;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_http_location_queue_t *) q;

            *(clcfp++) = lq->exact;
        }

        *clcfp = NULL;

        ngx_queue_split(locations, regex, &tail);
    }

#endif

    return NGX_OK;
}


/**
 * ngx_http_block->.
 * 
 * https://github.com/vislee/leevis.com/issues/68
 * 
 * 构建查找location的静态的二叉查找树
 * 
 * https://tengine.taobao.org/book/chapter_11.html#location
 * 
 * 有以下几个流程：
 *  ngx_http_join_exact_locations：将当前虚拟主机中 uri 字符串完全一致的 exact 和 inclusive 类型的 location 进行合并。
 *  ngx_http_create_locations_list：将前缀一致的location放到list链表中。
 *  ngx_http_create_locations_tree：构造location的树结构。
 * 
 * 
 * http://blog.chinaunix.net/uid-27767798-id-3759557.html
 * 
 */
static ngx_int_t
ngx_http_init_static_location_trees(ngx_conf_t *cf,
    ngx_http_core_loc_conf_t *pclcf)
{
    ngx_queue_t                *q, *locations;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_location_queue_t  *lq;

    locations = pclcf->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    if (ngx_queue_empty(locations)) {
        return NGX_OK;
    }

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_http_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    //调用ngx_http_join_exact_locations函数，把同名的两个location列表上的元素合并在一个元素上
    if (ngx_http_join_exact_locations(cf, locations) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_create_locations_list(locations, ngx_queue_head(locations));

    pclcf->static_locations = ngx_http_create_locations_tree(cf, locations, 0);
    if (pclcf->static_locations == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_add_location(ngx_conf_t *cf, ngx_queue_t **locations,
    ngx_http_core_loc_conf_t *clcf)
{
    ngx_http_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = ngx_palloc(cf->temp_pool,
                                sizeof(ngx_http_location_queue_t));
        if (*locations == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(*locations);
    }

    lq = ngx_palloc(cf->temp_pool, sizeof(ngx_http_location_queue_t));
    if (lq == NULL) {
        return NGX_ERROR;
    }

    if (clcf->exact_match
#if (NGX_PCRE)
        || clcf->regex
#endif
        || clcf->named || clcf->noname)
    {
        lq->exact = clcf;
        lq->inclusive = NULL;

    } else {
        lq->exact = NULL;
        lq->inclusive = clcf;
    }

    lq->name = &clcf->name;
    lq->file_name = cf->conf_file->file.name.data;
    lq->line = cf->conf_file->line;

    ngx_queue_init(&lq->list);

    ngx_queue_insert_tail(*locations, &lq->queue);

    if (ngx_http_escape_location_name(cf, clcf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_escape_location_name(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf)
{
    u_char     *p;
    size_t      len;
    uintptr_t   escape;

    escape = 2 * ngx_escape_uri(NULL, clcf->name.data, clcf->name.len,
                                NGX_ESCAPE_URI);

    if (escape) {
        len = clcf->name.len + escape;

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        clcf->escaped_name.len = len;
        clcf->escaped_name.data = p;

        ngx_escape_uri(p, clcf->name.data, clcf->name.len, NGX_ESCAPE_URI);

    } else {
        clcf->escaped_name = clcf->name;
    }

    return NGX_OK;
}


/**
 * 比较各个location，排序以后的顺序依次是
 *  1.精确匹配的路径和两类前缀匹配的路径(字母序，如果某个精确匹配的路径的名字和前缀匹配的路径相同，精确匹配的路径排在前面)
 *  2.正则路径(出现序)
 *  3.命名路径(字母序)
 *  4.无名路径(出现序)
 */
static ngx_int_t
ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t   *first, *second;
    ngx_http_location_queue_t  *lq1, *lq2;

    lq1 = (ngx_http_location_queue_t *) one;
    lq2 = (ngx_http_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;

    if (first->noname && !second->noname) {
        /* shift no named locations to the end */
        return 1;
    }

    if (!first->noname && second->noname) {
        /* shift no named locations to the end */
        return -1;
    }

    if (first->noname || second->noname) {
        /* do not sort no named locations */
        return 0;
    }

    if (first->named && !second->named) {
        /* shift named locations to the end */
        return 1;
    }

    if (!first->named && second->named) {
        /* shift named locations to the end */
        return -1;
    }

    if (first->named && second->named) {
        return ngx_strcmp(first->name.data, second->name.data);
    }

#if (NGX_PCRE)

    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }

#endif

    rc = ngx_filename_cmp(first->name.data, second->name.data,
                          ngx_min(first->name.len, second->name.len) + 1);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}


static ngx_int_t
ngx_http_join_exact_locations(ngx_conf_t *cf, ngx_queue_t *locations)
{
    ngx_queue_t                *q, *x;
    ngx_http_location_queue_t  *lq, *lx;

    q = ngx_queue_head(locations);

    while (q != ngx_queue_last(locations)) {

        x = ngx_queue_next(q);

        lq = (ngx_http_location_queue_t *) q;
        lx = (ngx_http_location_queue_t *) x;

        if (lq->name->len == lx->name->len
            && ngx_filename_cmp(lq->name->data, lx->name->data, lx->name->len)
               == 0)
        {
            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "duplicate location \"%V\" in %s:%ui",
                              lx->name, lx->file_name, lx->line);

                return NGX_ERROR;
            }

            lq->inclusive = lx->inclusive;

            ngx_queue_remove(x);

            continue;
        }

        q = ngx_queue_next(q);
    }

    return NGX_OK;
}


/**
 * ngx_http_block->ngx_http_init_static_location_trees->.
 * 
 * 将前缀一致的location放到list链表中。
 * 
 * http://blog.chinaunix.net/uid-27767798-id-3759557.html
 */
static void
ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    ngx_http_location_queue_t  *lq, *lx;

    //由于本函数存在递归调用，所以这个判断是递归的终止条件
    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (ngx_http_location_queue_t *) q;

    // 如果是完全匹配
    if (lq->inclusive == NULL) {
        // 如果不是inclusive类型的location，直接跳过，继续队列中下一个location的处理
        //如果这个节点是精准匹配那么这个节点，就不会作为某些节点的前缀，不用拥有tree节点
        ngx_http_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    // 从该location的下一个元素开始遍历队列
    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (ngx_http_location_queue_t *) x;


         //由于所有location已经按照顺序排列好，递归q节点的后继节点，如果后继节点的长度小于后缀节点的长度，那么可以断定，这个后继节点肯定和后缀节点不一样，并且不可能有共同的后缀；
         //如果后继节点和q节点的交集做比较，如果不同，就表示不是同一个前缀，所以可以看出，从q节点的location list应该是从q.next到x.prev节点

        // 找到第一个不以q的location做为前缀的location就退出循环
        // 比如当前队列location为：/a /ab /abc /b
        // 这里的q就是/a，x就是/b，中间的/ab和/abc都是以/a为前缀的，不会终止循环
        if (len > lx->name->len
            || ngx_filename_cmp(name, lx->name->data, len) != 0)
        {
            break;
        }
    }

    // 让出相同前缀的第一个元素，也就是q指向第二个
    q = ngx_queue_next(q);

    if (q == x) {   // 没有相同前缀的元素
        //如果q和x节点直接没有节点，那么就没有必要递归后面了产生q节点的location list，直接递归q的后继节点x，产生x节点location list
        ngx_http_create_locations_list(locations, x);
        return;
    }

    //location从q节点开始分割，那么现在location就是q节点之前的一段list
    ngx_queue_split(locations, q, &tail);
    //q节点的list初始为从q节点开始到最后的一段list
    ngx_queue_add(&lq->list, &tail);

    //原则上因为需要递归两段list，一个为p的location list（从p.next到x.prev），另一段为x.next到location的最后一个元素，
    //这里如果x已经是location的最后一个了，那么就没有必要递归x.next到location的这一段了，因为这一段都是空的。
    if (x == ngx_queue_sentinel(locations)) {
        ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    //到了这里可以知道需要递归两段location list了
    ngx_queue_split(&lq->list, x, &tail);   //再次分割，lq->list剩下p.next到x.prev的一段了
    ngx_queue_add(locations, &tail);        // 放到location 中去

    //递归p.next到x.prev
    ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    //递归x.next到location 最后了
    ngx_http_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

 /**
  * ngx_http_block->ngx_http_init_static_location_trees->.
  * 
  * https://www.taohui.pub/2021/08/09/nginx/URL%E6%98%AF%E5%A6%82%E4%BD%95%E5%85%B3%E8%81%94location%E9%85%8D%E7%BD%AE%E5%9D%97%E7%9A%84%EF%BC%9F/
  * http://blog.chinaunix.net/uid-27767798-id-3759557.html
  * 
  * 构建静态前缀匹配的多叉树，
  * 
  * 对于一个tree的生成最重要的就是，把当前的location list折中，中间的节点的前驱list作为左节点，后继list作为右节点，list指针作为tree节点，然后递归每个节点
  */
static ngx_http_location_tree_node_t *
ngx_http_create_locations_tree(ngx_conf_t *cf, ngx_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    ngx_queue_t                    *q, tail;
    ngx_http_location_queue_t      *lq;
    ngx_http_location_tree_node_t  *node;

     // 快慢指针获取链表中间偏右的节点。奇数个节点中间节点唯一，偶数个节点中间2个节点取第二个。
    // 符合构造树的习惯
    q = ngx_queue_middle(locations);

    lq = (ngx_http_location_queue_t *) q;
    //len是name减去prefix的长度
    len = lq->name->len - prefix;

    node = ngx_palloc(cf->pool,
                      offsetof(ngx_http_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->auto_redirect = (u_char) ((lq->exact && lq->exact->auto_redirect)
                           || (lq->inclusive && lq->inclusive->auto_redirect));

    node->len = (u_short) len;
    //可以看到实际node的name是父节点的增量（不存储公共前缀，也许这是为了节省空间）
    ngx_memcpy(node->name, &lq->name->data[prefix], len);

    //location队列是从头节点开始到q节点之前的节点，tail是q节点到location左右节点的队列
    ngx_queue_split(locations, q, &tail);

    if (ngx_queue_empty(locations)) {
        /*
         * ngx_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = ngx_http_create_locations_tree(cf, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    ngx_queue_remove(q);

    if (ngx_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = ngx_http_create_locations_tree(cf, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (ngx_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = ngx_http_create_locations_tree(cf, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}


/**
 * listen配置指令解析(ngx_http_core_listen)->ngx_http_add_listen
 * 
 * 
 * 将代表listen指令解析结果的lsopt加入到cmcf.ports动态数组中
 * 
 * 数据结构：
 * ngx_http_conf_port_t->ngx_http_conf_addr_t->ngx_http_core_srv_conf_t
 * port(80)->addr(127.0.0.1)->server(aa.com)
 *     |                |->server(bb.com)
 *     |->addr(192.168.23.11)->server(cc.com)
 *                          |->server(dd.com)
 * 
 */
ngx_int_t
ngx_http_add_listen(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_listen_opt_t *lsopt)
{
    in_port_t                   p;
    ngx_uint_t                  i;
    struct sockaddr            *sa;
    ngx_http_conf_port_t       *port;
    ngx_http_core_main_conf_t  *cmcf;

    //cmcf 是 http对应的核心配置，一个http对应一个，所以根据上述配置文件启动的ngx仅有一个
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    //如果为NULL, 则进行初始化
    if (cmcf->ports == NULL) {
        cmcf->ports = ngx_array_create(cf->temp_pool, 2,
                                       sizeof(ngx_http_conf_port_t));
        if (cmcf->ports == NULL) {
            return NGX_ERROR;
        }
    }

    // p 是 listen的端口，sa 有对应的协议：ipv4还是ipv6。
    sa = lsopt->sockaddr;
    p = ngx_inet_get_port(sa);

    //遍历所有监听端口,查找相同端口和协议
    port = cmcf->ports->elts;
    for (i = 0; i < cmcf->ports->nelts; i++) {

        //如果端口和协议类型不一致
        if (p != port[i].port
            || lsopt->type != port[i].type
            || sa->sa_family != port[i].family)
        {
            continue;
        }

        /* a port is already in the port list */

        // port 已经添加到了cmcf->ports数组中，
        // 检查addr 是否已经添加到port->addrs数组中，
        // 如果已经添加则调用ngx_http_add_server函数添加虚拟主机到addr->servers数组
        // 如果每有添加则调用ngx_http_add_address函数添加addr。
        return ngx_http_add_addresses(cf, cscf, &port[i], lsopt);
    }

    /* add a port to the port list */

    //新的端口

    // 添加port到cmcf->ports数组
    port = ngx_array_push(cmcf->ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->type = lsopt->type;
    port->port = p;
    port->addrs.elts = NULL;

    return ngx_http_add_address(cf, cscf, port, lsopt);
}


/**
 * 参考ngx_http_add_listen 方法
 * 
 * 检查addr是否已经添加到port->addrs数组中，
 * 如果已经添加则调用ngx_http_add_server函数添加虚拟主机到addr->servers数组
 * 如果没有添加则调用ngx_http_add_address函数添加addr。
 * 
 * 将listen指令解析结果lsopt 加入到port->addrs动态数组中
 * 
 * port(80)->addr(127.0.0.1)->server(aa.com)
       |                |->server(bb.com)
       |->addr(192.168.23.11)->server(cc.com)
                            |->server(dd.com)
 */
static ngx_int_t
ngx_http_add_addresses(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    ngx_uint_t             i, default_server, proxy_protocol,
                           protocols, protocols_prev;
    ngx_http_conf_addr_t  *addr;
#if (NGX_HTTP_SSL)
    ngx_uint_t             ssl;
#endif
#if (NGX_HTTP_V2)
    ngx_uint_t             http2;
#endif
#if (NGX_HTTP_V3)
    ngx_uint_t             quic;
#endif

    /*
     * we cannot compare whole sockaddr struct's as kernel
     * may fill some fields in inherited sockaddr struct's
     */

    addr = port->addrs.elts;

    //遍历该port下的多个监听地址
    for (i = 0; i < port->addrs.nelts; i++) {

        //如果地址相同
        if (ngx_cmp_sockaddr(lsopt->sockaddr, lsopt->socklen,
                             addr[i].opt.sockaddr,
                             addr[i].opt.socklen, 0)
            != NGX_OK)
        {
            continue;
        }

        /* the address is already in the address list */

        //已经有相同地址了，将其添加到addr对应的servers动态数组中
        if (ngx_http_add_server(cf, cscf, &addr[i]) != NGX_OK) {
            return NGX_ERROR;
        }

        /* preserve default_server bit during listen options overwriting */
        default_server = addr[i].opt.default_server;

        proxy_protocol = lsopt->proxy_protocol || addr[i].opt.proxy_protocol;
        protocols = lsopt->proxy_protocol;
        protocols_prev = addr[i].opt.proxy_protocol;

#if (NGX_HTTP_SSL)
        ssl = lsopt->ssl || addr[i].opt.ssl;
        protocols |= lsopt->ssl << 1;
        protocols_prev |= addr[i].opt.ssl << 1;
#endif
#if (NGX_HTTP_V2)
        http2 = lsopt->http2 || addr[i].opt.http2;
        protocols |= lsopt->http2 << 2;
        protocols_prev |= addr[i].opt.http2 << 2;
#endif
#if (NGX_HTTP_V3)
        quic = lsopt->quic || addr[i].opt.quic;
#endif

        //一个address只能有一个指令设置监听选项
        if (lsopt->set) {

            if (addr[i].opt.set) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate listen options for %V",
                                   &addr[i].opt.addr_text);
                return NGX_ERROR;
            }

            //更新addr[i] 的监听选项指针
            addr[i].opt = *lsopt;
        }

        /* check the duplicate "default" server for this address:port */

        //如果是default_server
        if (lsopt->default_server) {

            //出现了个default_server
            if (default_server) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate default server for %V",
                                   &addr[i].opt.addr_text);
                return NGX_ERROR;
            }

            default_server = 1;
            //设置default_server执行的server{}配置结构体
            addr[i].default_server = cscf;
        }

        /* check for conflicting protocol options */

        if ((protocols | protocols_prev) != protocols_prev) {

            /* options added */

            if ((addr[i].opt.set && !lsopt->set)
                || addr[i].protocols_changed
                || (protocols | protocols_prev) != protocols)
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols_prev;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else if ((protocols_prev | protocols) != protocols) {

            /* options removed */

            if (lsopt->set
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
            addr[i].protocols_changed = 1;

        } else {

            /* the same options */

            if ((lsopt->set && addr[i].protocols_changed)
                || (addr[i].protocols_set && protocols != addr[i].protocols))
            {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "protocol options redefined for %V",
                                   &addr[i].opt.addr_text);
            }

            addr[i].protocols = protocols;
            addr[i].protocols_set = 1;
        }

        addr[i].opt.default_server = default_server;
        addr[i].opt.proxy_protocol = proxy_protocol;
#if (NGX_HTTP_SSL)
        addr[i].opt.ssl = ssl;
#endif
#if (NGX_HTTP_V2)
        addr[i].opt.http2 = http2;
#endif
#if (NGX_HTTP_V3)
        addr[i].opt.quic = quic;
#endif

        return NGX_OK;
    }

    /* add the address to the addresses list that bound to this port */

    //port->address. 将lsopt加入到port->address动态数组中
    return ngx_http_add_address(cf, cscf, port, lsopt);
}


/*
 * add the server address, the server names and the server core module
 * configurations to the port list
 */

/**
 * 将listen指令的解析结果lsopt加入到port->address动态数组中
 * 
 * port: ngx_http_core_main_conf_t->ports的一个元素
 * lsopt: 一条listen指令的解析结果
 * 
 * 数据结构：
 * ngx_http_conf_port_t->ngx_http_conf_addr_t->ngx_http_core_srv_conf_t
 * port(80)->addr(127.0.0.1)->server(aa.com)
 *     |                |->server(bb.com)
 *     |->addr(192.168.23.11)->server(cc.com)
 *                          |->server(dd.com)
 **/ 
static ngx_int_t
ngx_http_add_address(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_port_t *port, ngx_http_listen_opt_t *lsopt)
{
    ngx_http_conf_addr_t  *addr;

    //如果为NULL，则进行初始化
    if (port->addrs.elts == NULL) {
        if (ngx_array_init(&port->addrs, cf->temp_pool, 4,
                           sizeof(ngx_http_conf_addr_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

#if (NGX_HTTP_V2 && NGX_HTTP_SSL                                              \
     && !defined TLSEXT_TYPE_application_layer_protocol_negotiation)

    if (lsopt->http2 && lsopt->ssl) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "nginx was built with OpenSSL that lacks ALPN "
                           "support, HTTP/2 is not enabled for %V",
                           &lsopt->addr_text);
    }

#endif

    //添加一个代表监听地址的数据结构ngx_http_conf_addr_t
    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    //设置相关属性
    addr->opt = *lsopt;
    addr->protocols = 0;
    addr->protocols_set = 0;
    addr->protocols_changed = 0;
    addr->hash.buckets = NULL;
    addr->hash.size = 0;
    addr->wc_head = NULL;
    addr->wc_tail = NULL;
#if (NGX_PCRE)
    addr->nregex = 0;
    addr->regex = NULL;
#endif
    //只是临时的default_server
    addr->default_server = cscf;
    addr->servers.elts = NULL;

    return ngx_http_add_server(cf, cscf, addr);
}


/* add the server core module configuration to the address:port */

/**
 * ngx_http_add_listen->ngx_http_add_addresses
 * 
 * 一个ngx_http_conf_addr_t表示的监听地址下可以有多个虚拟主机 server_name。
 * 
 * 此函数将表示server{}配置块的cscf加入到addr->servers中
 * 
 */
static ngx_int_t
ngx_http_add_server(ngx_conf_t *cf, ngx_http_core_srv_conf_t *cscf,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                  i;
    ngx_http_core_srv_conf_t  **server;

    //如果为NULL，则进行初始化
    if (addr->servers.elts == NULL) {
        if (ngx_array_init(&addr->servers, cf->temp_pool, 4,
                           sizeof(ngx_http_core_srv_conf_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        //查找是否有相同表示server{}结构的引用了。有则表示配置了重复的listen指令在同一个server{}配置块中
        server = addr->servers.elts;
        for (i = 0; i < addr->servers.nelts; i++) {
            if (server[i] == cscf) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "a duplicate listen %V",
                                   &addr->opt.addr_text);
                return NGX_ERROR;
            }
        }
    }

    //添加一个元素
    server = ngx_array_push(&addr->servers);
    if (server == NULL) {
        return NGX_ERROR;
    }

    *server = cscf;

    return NGX_OK;
}


/**
 * ngx_http_block()->ngx_http_optimize_servers
 * 
 * ngx_http_optimize_servers：处理Nginx服务的监听套接字
 * 说明：主要遍历Nginx服务器提供的端口，然后根据每一个IP地址:port这种配置创建一个监听套接字
 * ngx_http_init_listening：初始化监听套接字
 * 
 * https://tengine.taobao.org/book/chapter_11.html#id12
 * 
 * 
 * 一个如192.168.1.1:8080下可以配置多个虚拟主机。虚拟主机支持前缀、后缀、正则匹配。
 * 此方法遍历所有监听端口，对于每个监听端口，遍历其所有监听地址，对于每个地址，建立server_names_hash
 * 
 */
static ngx_int_t
ngx_http_optimize_servers(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{
    ngx_uint_t             p, a;
    ngx_http_conf_port_t  *port;
    ngx_http_conf_addr_t  *addr;

    if (ports == NULL) {
        return NGX_OK;
    }

    /* 根据Nginx配置的监听端口号进行遍历  */
    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        //根据wildcard和bind两个字段进行排序
        // a wildcard address must be the last resort */
        // shift explicit bind()ed addresses to the start */
        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_http_conf_addr_t), ngx_http_cmp_conf_addrs);

        /*
         * check whether all name-based servers have the same
         * configuration as a default server for given address:port
         */

        //遍历该端口下的多个监听地址 listten 127.0.0.1:8080 192.186.1.1:8080
        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {

            //servers.nelts > 1 说明配置了虚拟主机 server_name
            if (addr[a].servers.nelts > 1
#if (NGX_PCRE)
                || addr[a].default_server->captures
#endif
               )
            {
                //遍历所有监听端口，对于每个监听端口，遍历其所有监听地址，对于每个地址，建立server_names_hash
                if (ngx_http_server_names(cf, cmcf, &addr[a]) != NGX_OK) {
                    return NGX_ERROR;
                }
            }
        }

        //初始化监听结构体 ngx_listening_t
        if (ngx_http_init_listening(cf, &port[p]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/**
 * 多个server{} 中listen指令配置的监听地址相同，但server_name配置的域名不同
 * 
 * 此方法用来初始化多个server_name指令配置的wildcard_hash表。 构建"server_names_hash"
 * 
 * addr: 表示监听地址
 * addr->servers: 表示该监听地址下的多个server{}配置块(多个虚拟主机)
 * 
 * 把该addr->servers数组所有的虚拟主机初始化为一个hash表保存到addr->hash上。
 * 支持前置通配符的保存到addr->wc_head，后置通配符的保存到addr->wc_tail，
 * 正则表达式的保存到addr->regex
 * 
 */
static ngx_int_t
ngx_http_server_names(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf,
    ngx_http_conf_addr_t *addr)
{
    ngx_int_t                   rc;
    ngx_uint_t                  n, s;
    ngx_hash_init_t             hash;
    ngx_hash_keys_arrays_t      ha;
    ngx_http_server_name_t     *name;
    ngx_http_core_srv_conf_t  **cscfp;
#if (NGX_PCRE)
    ngx_uint_t                  regex, i;

    regex = 0;
#endif

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    //创建一个临时内存池，用于构建查找server_name的前置、后置查找hash
    ha.temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    ha.pool = cf->pool;

    //初始化 ngx_hash_keys_arrays_t ha
    if (ngx_hash_keys_array_init(&ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }

    //向ha中添加key
    cscfp = addr->servers.elts;

    //遍历一个监听地址下的多个server{}配置块
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        //一个server{}配置块下的server_name指令也可以配置多个虚拟域名
        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

#if (NGX_PCRE)
            //表示是正则匹配
            if (name[n].regex) {
                regex++;        //记录当前addr下配置的正则匹配的虚拟域名个数
                continue;
            }
#endif

            //将key加入到用于初始化hash表的ngx_hash_keys_arrays_t ha
            rc = ngx_hash_add_key(&ha, &name[n].name, name[n].server,
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                goto failed;
            }

            if (rc == NGX_DECLINED) {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "invalid server name or wildcard \"%V\" on %V",
                              &name[n].name, &addr->opt.addr_text);
                goto failed;
            }

            if (rc == NGX_BUSY) {
                ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                              "conflicting server name \"%V\" on %V, ignored",
                              &name[n].name, &addr->opt.addr_text);
            }
        }
    }

    //构建server_names_hash
    hash.key = ngx_hash_key_lc;
    hash.max_size = cmcf->server_names_hash_max_size;
    hash.bucket_size = cmcf->server_names_hash_bucket_size;
    hash.name = "server_names_hash";
    hash.pool = cf->pool;

    //初始化完全匹配 server name的散列表
    if (ha.keys.nelts) {
        hash.hash = &addr->hash;    //完全匹配 server name的散列表
        hash.temp_pool = NULL;

        if (ngx_hash_init(&hash, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            goto failed;
        }
    }

    //初始化通配符前置的散列表
    if (ha.dns_wc_head.nelts) {

        ngx_qsort(ha.dns_wc_head.elts, (size_t) ha.dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_head.elts,
                                   ha.dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        //通配符前置的散列表
        addr->wc_head = (ngx_hash_wildcard_t *) hash.hash;
    }

     //初始化通配符后置的散列表
    if (ha.dns_wc_tail.nelts) {

        ngx_qsort(ha.dns_wc_tail.elts, (size_t) ha.dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = ha.temp_pool;

        if (ngx_hash_wildcard_init(&hash, ha.dns_wc_tail.elts,
                                   ha.dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        //通配符后置的散列表
        addr->wc_tail = (ngx_hash_wildcard_t *) hash.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

#if (NGX_PCRE)

    if (regex == 0) {
        return NGX_OK;
    }

    /**开始处理正则匹配规则 */

    addr->nregex = regex;
    //创建表示正则匹配server_name的数组
    addr->regex = ngx_palloc(cf->pool, regex * sizeof(ngx_http_server_name_t));
    if (addr->regex == NULL) {
        return NGX_ERROR;
    }

    i = 0;

    //遍历同一addr关联的多个server{}配置结构体
    for (s = 0; s < addr->servers.nelts; s++) {

        name = cscfp[s]->server_names.elts;

        //变量同一个server{}配置结构体中server_name配置的多个虚拟主机
        for (n = 0; n < cscfp[s]->server_names.nelts; n++) {
            if (name[n].regex) {
                //赋值
                addr->regex[i++] = name[n];
            }
        }
    }

#endif

    return NGX_OK;

failed:

    ngx_destroy_pool(ha.temp_pool);

    return NGX_ERROR;
}


/**
 * 一个比较排序表示监听地址 ngx_http_conf_addr_t 的方法
 * 
 * 主要根据wildcard和bind两个字段进行比较
 */
static ngx_int_t
ngx_http_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_http_conf_addr_t  *first, *second;

    first = (ngx_http_conf_addr_t *) one;
    second = (ngx_http_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard address must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}


static int ngx_libc_cdecl
ngx_http_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}


/**
 * ngx_http_block->ngx_http_optimize_servers->.
 * 初始化监听结构体 ngx_listening_t
 * 
 * *port: 本次要初始化的监听端口
 * 
 * 组成的数据结构为：
 * cycle->listening(ngx_listening_t)->ngx_http_port_t->addr
 * cycle->listening->ls(127.0.0.1:80)->servers->addr(127.0.0.1)->conf.vn(aa.com)
 *             |                                           |->conf.vn(bb.com)
 *             |->ls(192.168.23.11:80)->servers->addr(192.168.23.11)->conf.vn(cc.com)
 *                                                                 |->conf.vn(dd.com)
 * 
 */
static ngx_int_t
ngx_http_init_listening(ngx_conf_t *cf, ngx_http_conf_port_t *port)
{
    ngx_uint_t                 i, last, bind_wildcard;
    ngx_listening_t           *ls;
    ngx_http_port_t           *hport;
    ngx_http_conf_addr_t      *addr;

    addr = port->addrs.elts;
    last = port->addrs.nelts;

    /*
     * If there is a binding to an "*:port" then we need to bind() to
     * the "*:port" only and ignore other implicit bindings.  The bindings
     * have been already sorted: explicit bindings are on the start, then
     * implicit bindings go, and wildcard binding is in the end.
     */

    //判断是否有*:port这种情况， 如果有这种配置的，需要bind这个忽略指定了IP的其他的配置 
    if (addr[last - 1].opt.wildcard) {
        addr[last - 1].opt.bind = 1;
        bind_wildcard = 1;

    } else {
        bind_wildcard = 0;
    }

    i = 0;

    //遍历本端口下所有的监听地址，每个地址创建一个 ngx_listening_t 结构体
    while (i < last) {

        //如果有*:port这种情况，那么只有一个地址需要绑定，其他的直接continue
        if (bind_wildcard && !addr[i].opt.bind) {
            // i 这个值最终就代表了有多少个不用bind被包含在宽绑定里的IP。
            i++;
            continue;
        }

        //创建 ngx_listening_t，初始化其相关属性， 并将其加入到cycle->listening动态数组中
        ls = ngx_http_add_listening(cf, &addr[i]);
        if (ls == NULL) {
            return NGX_ERROR;
        }

        hport = ngx_pcalloc(cf->pool, sizeof(ngx_http_port_t));
        if (hport == NULL) {
            return NGX_ERROR;
        }

        ls->servers = hport;

        hport->naddrs = i + 1;

        switch (ls->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            if (ngx_http_add_addrs6(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
#endif
        default: /* AF_INET */
            //将addr加入到hport->addrs
            if (ngx_http_add_addrs(cf, hport, addr) != NGX_OK) {
                return NGX_ERROR;
            }
            break;
        }

        addr++;
        last--;
    }

    return NGX_OK;
}


/**
 * 
整个流程如下（https://blog.csdn.net/initphp/article/details/53728970）：

1.在Nginx main函数的ngx_init_cycle()方法中，调用了ngx_open_listening_sockets函数，这个函数负责将创建的监听套接字进行套接字选项的设置（比如非阻塞、接受发送的缓冲区、绑定、监听处理）

2.HTTP模块初始化优先于Event模块，HTTP模块通过ngx_http_block()方法进行初始化，然后调用ngx_http_optimize_servers()进行套接字的创建和初始化（ngx_http_init_listening、ngx_http_add_listening、ngx_create_listening）。根据每一个IP地址:port这种配置创建监听套接字。

3.ngx_http_add_listening函数，还会将ls->handler监听套接字的回调函数设置为ngx_http_init_connection。ngx_http_init_connection此函数主要初始化一个客户端连接connection。

4.Event模块的初始化主要调用ngx_event_process_init()函数。该函数每个worker工作进程都会初始化调用。然后设置read/write的回调函数。

5.ngx_event_process_init函数中，会将接收客户端连接的事件，设置为rev->handler=ngx_event_accept方法，ngx_event_accept方法，只有在第一次客户端和Nginx服务端创建连接关系的时候调用。

6.当客户端有连接上来，Nginx工作进程就会进入事件循环（epoll事件循环函数：ngx_epoll_process_events），发现有read读取的事件，则会调用ngx_event_accept函数。

7.调用ngx_event_accept函数，会调用ngx_get_connection方法，得到一个客户端连接结构：ngx_connection_t结构。ngx_event_accept函数最终会调用监听套接字的handler回调函数，ls->handler(c);  。

8.从流程3中，我们知道ls->handler的函数对应ngx_http_init_connection方法。此方法主要初始化客户端的连接ngx_connection_t，并将客户端连接read读取事件的回调函数修改成rev->handler = ngx_http_wait_request_handler

9.也就是说，当客户端连接上来，第一次事件循环的read事件会调用回调函数：ngx_event_accept函数；而后续的read事件的handler已经被ngx_http_init_connection方法修改掉，改成了ngx_http_wait_request_handler函数了。所以客户端的读取事件都会走ngx_http_wait_request_handler函数。

10.ngx_http_wait_request_handler函数也是整个HTTP模块的数据处理的入口函数了。

 */

/**
 * 
 * ngx_http_block->ngx_http_optimize_servers->ngx_http_init_listening
 * 
 * 创建 ngx_listening_t，初始化其相关属性， 并将其加入到cycle->listening动态数组中
 */
static ngx_listening_t *
ngx_http_add_listening(ngx_conf_t *cf, ngx_http_conf_addr_t *addr)
{
    ngx_listening_t           *ls;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;

    //创建一个ngx_listening_t
    ls = ngx_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
    if (ls == NULL) {
        return NULL;
    }

    //标识其二进制地址已经转为文本格式地址addr_text
    ls->addr_ntop = 1;

    //设置新连接事件的回调方法为 ngx_http_init_connection。（当accept()到一条新连接后，调用此回调初始化ngx_connection_t）
    ls->handler = ngx_http_init_connection;

    //在根据Host查找到具体的server{}之前，先用default_server的配置
    cscf = addr->default_server;
    ls->pool_size = cscf->connection_pool_size;

    clcf = cscf->ctx->loc_conf[ngx_http_core_module.ctx_index];

    //设置log相关方法
    ls->logp = clcf->error_log;
    ls->log.data = &ls->addr_text;
    ls->log.handler = ngx_accept_log_error;

#if (NGX_WIN32)
    {
    ngx_iocp_conf_t  *iocpcf = NULL;

    if (ngx_get_conf(cf->cycle->conf_ctx, ngx_events_module)) {
        iocpcf = ngx_event_get_conf(cf->cycle->conf_ctx, ngx_iocp_module);
    }
    if (iocpcf && iocpcf->acceptex_read) {
        ls->post_accept_buffer_size = cscf->client_header_buffer_size;
    }
    }
#endif

    //设置相关属性
    ls->type = addr->opt.type;
    ls->backlog = addr->opt.backlog;
    ls->rcvbuf = addr->opt.rcvbuf;
    ls->sndbuf = addr->opt.sndbuf;

    ls->keepalive = addr->opt.so_keepalive;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    ls->keepidle = addr->opt.tcp_keepidle;
    ls->keepintvl = addr->opt.tcp_keepintvl;
    ls->keepcnt = addr->opt.tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    ls->accept_filter = addr->opt.accept_filter;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ls->deferred_accept = addr->opt.deferred_accept;
#endif

#if (NGX_HAVE_INET6)
    ls->ipv6only = addr->opt.ipv6only;
#endif

#if (NGX_HAVE_SETFIB)
    ls->setfib = addr->opt.setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    ls->fastopen = addr->opt.fastopen;
#endif

#if (NGX_HAVE_REUSEPORT)
    ls->reuseport = addr->opt.reuseport;
#endif

    ls->wildcard = addr->opt.wildcard;

#if (NGX_HTTP_V3)
    ls->quic = addr->opt.quic;
#endif

    return ls;
}


/**
 * ngx_http_block->ngx_http_optimize_servers->ngx_http_init_listening
 * 
 * 将addr代表的一个监听地址加入到hport->addrs
 */
static ngx_int_t
ngx_http_add_addrs(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in_addr_t        *addrs;
    struct sockaddr_in        *sin;
    ngx_http_virtual_names_t  *vn;

    // addrs 数组包含了addr以及对应的虚拟主机
    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;
        addrs[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        addrs[i].conf.http2 = addr[i].opt.http2;
#endif
#if (NGX_HTTP_V3)
        addrs[i].conf.quic = addr[i].opt.quic;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        // addr 下的虚拟主机
        addrs[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_http_add_addrs6(ngx_conf_t *cf, ngx_http_port_t *hport,
    ngx_http_conf_addr_t *addr)
{
    ngx_uint_t                 i;
    ngx_http_in6_addr_t       *addrs6;
    struct sockaddr_in6       *sin6;
    ngx_http_virtual_names_t  *vn;

    hport->addrs = ngx_pcalloc(cf->pool,
                               hport->naddrs * sizeof(ngx_http_in6_addr_t));
    if (hport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = hport->addrs;

    for (i = 0; i < hport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;
        addrs6[i].conf.default_server = addr[i].default_server;
#if (NGX_HTTP_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
#if (NGX_HTTP_V2)
        addrs6[i].conf.http2 = addr[i].opt.http2;
#endif
#if (NGX_HTTP_V3)
        addrs6[i].conf.quic = addr[i].opt.quic;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;

        if (addr[i].hash.buckets == NULL
            && (addr[i].wc_head == NULL
                || addr[i].wc_head->hash.buckets == NULL)
            && (addr[i].wc_tail == NULL
                || addr[i].wc_tail->hash.buckets == NULL)
#if (NGX_PCRE)
            && addr[i].nregex == 0
#endif
            )
        {
            continue;
        }

        vn = ngx_palloc(cf->pool, sizeof(ngx_http_virtual_names_t));
        if (vn == NULL) {
            return NGX_ERROR;
        }

        // addr 下的虚拟主机
        addrs6[i].conf.virtual_names = vn;

        vn->names.hash = addr[i].hash;
        vn->names.wc_head = addr[i].wc_head;
        vn->names.wc_tail = addr[i].wc_tail;
#if (NGX_PCRE)
        vn->nregex = addr[i].nregex;
        vn->regex = addr[i].regex;
#endif
    }

    return NGX_OK;
}

#endif


/**
 * 解析types类型数据，一般为多个，组成一个动态数组，元素类型为 ngx_hash_key_t
 * 
 * 配合合并函数ngx_http_merge_types，最终合并结果为一个hash，进行快速查找
 * 
 * 使用场景如content_type的快速查找
 * 
 */
char *
ngx_http_types_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_array_t     **types;
    ngx_str_t        *value, *default_type;
    ngx_uint_t        i, n, hash;
    ngx_hash_key_t   *type;

    //元素类型为 ngx_hash_key_t 的动态数组
    types = (ngx_array_t **) (p + cmd->offset);

    if (*types == (void *) -1) {
        return NGX_CONF_OK;
    }

    default_type = cmd->post;

    //如果为NULL，则进行动态数组初始化
    if (*types == NULL) {
        *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
        if (*types == NULL) {
            return NGX_CONF_ERROR;
        }

        //如果有默认值
        if (default_type) {
            type = ngx_array_push(*types);      //将默认值加入动态数组
            if (type == NULL) {
                return NGX_CONF_ERROR;
            }

            type->key = *default_type;
            type->key_hash = ngx_hash_key(default_type->data,
                                          default_type->len);       //计算hash
            //value设置为固定值
            type->value = (void *) 4;
        }
    }

    value = cf->args->elts;

    //遍历配置指令的每个参数
    for (i = 1; i < cf->args->nelts; i++) {

        //有*，表示所有，直接将types置为-1,返回
        if (value[i].len == 1 && value[i].data[0] == '*') {
            *types = (void *) -1;
            return NGX_CONF_OK;
        }

        //转小写，计算hash
        hash = ngx_hash_strlow(value[i].data, value[i].data, value[i].len);
        value[i].data[value[i].len] = '\0';

        //遍历动态数组，检查是否有重复
        type = (*types)->elts;
        for (n = 0; n < (*types)->nelts; n++) {

            //对于重复元素，只是打印WARN日志，忽略重复元素，继续处理
            if (ngx_strcmp(value[i].data, type[n].key.data) == 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate MIME type \"%V\"", &value[i]);
                goto next;
            }
        }

        //增加一个元素
        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_CONF_ERROR;
        }

        type->key = value[i];
        type->key_hash = hash;
        type->value = (void *) 4;

    next:

        continue;
    }

    return NGX_CONF_OK;
}


/**
 * 合并动态数组类型的配置值，同时初始化hash表。应用场景如content_type的查找
 * 
 * 合并的主要结果是hash表。对动态数组不会执行合并操作
 * 
 * keys：current keys
 * types_hash：待构建的hash表
 * 
 */
char *
ngx_http_merge_types(ngx_conf_t *cf, ngx_array_t **keys, ngx_hash_t *types_hash,
    ngx_array_t **prev_keys, ngx_hash_t *prev_types_hash,
    ngx_str_t *default_types)
{
    ngx_hash_init_t  hash;

    //如果key不为空
    if (*keys) {

        if (*keys == (void *) -1) {
            return NGX_CONF_OK;
        }

        //构建用于初始化hash表的 ngx_hash_init_t  hash
        hash.hash = types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        //初始化hash
        if (ngx_hash_init(&hash, (*keys)->elts, (*keys)->nelts) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    //如果prev_types_hash为NULL
    if (prev_types_hash->buckets == NULL) {

        if (*prev_keys == NULL) {       //如果prev_keys也为NULL，使用默认值

            //使用默认值进行初始化
            if (ngx_http_set_default_types(cf, prev_keys, default_types)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }

        } else if (*prev_keys == (void *) -1) {
            *keys = *prev_keys;
            return NGX_CONF_OK;
        }

        hash.hash = prev_types_hash;
        hash.key = NULL;
        hash.max_size = 2048;
        hash.bucket_size = 64;
        hash.name = "test_types_hash";
        hash.pool = cf->pool;
        hash.temp_pool = NULL;

        //初始化prev_types_hash
        if (ngx_hash_init(&hash, (*prev_keys)->elts, (*prev_keys)->nelts)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    *types_hash = *prev_types_hash;

    return NGX_CONF_OK;

}


/**
 * 将ngx_str_t表示的字符串数组构建为types指向的元素为ngx_hash_key_t的动态数组
 */
ngx_int_t
ngx_http_set_default_types(ngx_conf_t *cf, ngx_array_t **types,
    ngx_str_t *default_type)
{
    ngx_hash_key_t  *type;

    //创建一个单元素的动态数组
    *types = ngx_array_create(cf->temp_pool, 1, sizeof(ngx_hash_key_t));
    if (*types == NULL) {
        return NGX_ERROR;
    }

    while (default_type->len) {

        //向types中添加一个元素
        type = ngx_array_push(*types);
        if (type == NULL) {
            return NGX_ERROR;
        }

        type->key = *default_type;      //key
        type->key_hash = ngx_hash_key(default_type->data,       //hash
                                      default_type->len);
        type->value = (void *) 4;       //value

        default_type++;
    }

    return NGX_OK;
}
