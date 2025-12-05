#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


/**
 * loc级别配置结构体
 */
typedef struct {
    //全局的global_State
    lua_State   *vm;
    //access_by_lua lua脚本
    ngx_str_t   script;
} ngx_http_lua_test_loc_conf_t;


/**
 * 模块上下文结构体
 */
typedef struct {
    lua_State           *vm;
    int                  ref;
    ngx_http_handler_pt  resume_handler;
    int                  entered_access_phase;
    //有一个statu的成员，执行Lua脚本后检查status的值, 如果大于等于200,则向客户端返回
    int                  status;
} ngx_http_lua_test_ctx_t;


static ngx_int_t
ngx_http_lua_test_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_lua_test_init(ngx_conf_t *cf);
static void *
ngx_http_lua_test_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t
ngx_http_lua_test_new_thread(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_test_ctx_t *ctx);
static ngx_int_t
ngx_http_lua_test_del_thread(ngx_http_lua_test_ctx_t *ctx);
static int
ngx_http_lua_test_ngx_exit(lua_State *L);
static ngx_int_t
ngx_http_lua_test_sleep_resume(ngx_http_request_t *r);
static void
ngx_http_lua_test_sleep_handler(ngx_event_t *ev);
static int
ngx_http_lua_test_ngx_sleep(lua_State *L);
static int
ngx_http_lua_test_ngx_get_method(lua_State *L);



static ngx_command_t ngx_http_lua_test_commands[] = {
    {
        ngx_string("access_by_lua"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_lua_test_loc_conf_t, script),
        NULL },
    ngx_null_command
};


/**
 * 
 * http://www.qlee.in/openresty/2017/02/26/nginx-lua-coroutine-scheduler-1/
 * 
 * export LUAJIT_INC=/usr/local/Cellar/openresty/1.21.4.1_1/luajit/include/luajit-2.1
 * export LUAJIT_LIB=/usr/local/Cellar/openresty/1.21.4.1_1/luajit/lib
 *
 * auto/configure --prefix=`pwd`/tmp  --with-debug \
 * --with-cc-opt='-O0 -I /usr/local/Cellar/openresty/1.21.4.1_1/luajit/include/luajit-2.1' \
 * --with-ld-opt='-lluajit-5.1' --add-module=z-dev-example/my/ngx_http_lua_test
 */


static ngx_http_module_t  ngx_http_lua_test_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_lua_test_init,            /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_lua_test_create_loc_conf, /* create location configuration */
    NULL   /* merge location configuration */
};


ngx_module_t  ngx_http_lua_test_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_test_module_ctx,         /* module context */
    ngx_http_lua_test_commands,            /* module directives */
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


#define ngx_http_lua_test_req_key    "__ngx_req"
static char ngx_http_lua_test_coroutines_key;


/**
 * 创建用于执行lua脚本的协程， 并注入相关api
 */
static ngx_int_t
ngx_http_lua_test_new_thread(lua_State *L, ngx_http_request_t *r,
    ngx_http_lua_test_ctx_t *ctx)
{
    //创建一个协程
    lua_State *vm = lua_newthread(L);

    //以下两行将索引&ngx_http_lua_test_coroutines_key指向的表压入堆栈
    lua_pushlightuserdata(vm, &ngx_http_lua_test_coroutines_key);
    lua_rawget(vm, LUA_REGISTRYINDEX);

    //Lua中GC采用标记清除的方式，每个变量必须有其他变量引用，否则就可能被GC回收掉。
    //Lua中的协程也是一个GC对象，多个协程同时存在时，必须为每个协程添加引用，以免被回收掉。
    /* 引用协程以免GC的影响 */
    ctx->ref = luaL_ref(vm, -1);    //在上边的表里为vm创建一个引用
    ctx->vm = vm;
    ctx->entered_access_phase = 1;

    /* 注册ngx API */
    lua_createtable(vm, 0, 0);
    //exit = ngx_http_lua_test_ngx_exit
    lua_pushcfunction(vm, ngx_http_lua_test_ngx_exit);
    lua_setfield(vm, -2, "exit");

    //sleep = ngx_http_lua_test_ngx_sleep
    lua_pushcfunction(vm, ngx_http_lua_test_ngx_sleep);
    lua_setfield(vm, -2, "sleep");

    //get_method = ngx_http_lua_test_ngx_sleep
    lua_pushcfunction(vm, ngx_http_lua_test_ngx_get_method);
    lua_setfield(vm, -2, "get_method");

    //ngx={ext=..., sleep=...}
    lua_setglobal(vm, "ngx");

    /* 将r保存到全局变量中，key为ngx_http_lua_test_req_key */
    lua_pushlightuserdata(vm, r);
    //__ngx_req = r
    lua_setglobal(vm, ngx_http_lua_test_req_key);

    return NGX_OK;
}


/**
 * 释放协程的引用
 */
static ngx_int_t
ngx_http_lua_test_del_thread(ngx_http_lua_test_ctx_t *ctx)
{
    //将vm从&ngx_http_lua_test_coroutines_key指向的表中移除
    lua_State *L = ctx->vm;
    lua_pushlightuserdata(L, &ngx_http_lua_test_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    //移除后可能会被垃圾收集
    luaL_unref(L, -1, ctx->ref);
    ctx->ref = LUA_NOREF;
    return NGX_OK;
}


/**
 * access阶段的handler
 */
static ngx_int_t
ngx_http_lua_test_handler(ngx_http_request_t *r)
{
    ngx_http_lua_test_loc_conf_t *tlcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_test_module);
    if (tlcf->script.len == 0) {
        return NGX_DECLINED;
    }

    ngx_http_lua_test_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_test_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        ngx_http_set_ctx(r, ctx, ngx_http_lua_test_module);
    }

    //如果为true，则是第二次执行
    if (ctx->entered_access_phase) {
        //恢复lua协程的执行, ret为lua_resume的返回值， 返回值为0时，脚本执行结束;返回值为1时，协程被挂起; 返回其它值时，脚本执行出错。
        int ret = ctx->resume_handler(r);
        if (ret == 1) return NGX_DONE;

        ngx_http_lua_test_del_thread(ctx);
        if (ctx->status == 403)
            return NGX_HTTP_FORBIDDEN;
        if (ctx->status >= 200) {
            return ctx->status;
        }
        return NGX_DECLINED;
    }

    //创建一个lua协程，执行lua代码
    ngx_http_lua_test_new_thread(tlcf->vm, r, ctx);

    /*  加载一段Lua代码，将其编译成Lua虚拟机的字节码 */
    int ret = luaL_loadstring(ctx->vm, (const char *)tlcf->script.data);
    if (ret != 0) {
        return NGX_ERROR;
    }

    /*  调用前面加载的Lua代码 */
    ret = lua_resume(ctx->vm, 0);
    if (ret == 1) {
        return NGX_AGAIN;
    }

    ngx_http_lua_test_del_thread(ctx);
    if (ctx->status == 403) {
        return NGX_HTTP_FORBIDDEN;
    }
    if (ctx->status >= 200) {
        return ctx->status;
    }

    return NGX_DECLINED;
}


/**
 * ngx.exit(status)
 */
static int
ngx_http_lua_test_ngx_exit(lua_State *L)
{
    int status;
    status = luaL_checkint(L, 1);

    ngx_http_request_t *r;
    //获取当前请求
    lua_getglobal(L, ngx_http_lua_test_req_key);
    r = lua_touserdata(L, -1);

    //获取当前上下文结构体
    ngx_http_lua_test_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_test_module);
    //设置status
    ctx->status = status;

    lua_pushboolean(L, 1);
    return 1;
}


/**
 * sleep后，继续协程的执行
 */
static ngx_int_t
ngx_http_lua_test_sleep_resume(ngx_http_request_t *r)
{
    ngx_http_lua_test_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_test_module);

    int rc = lua_resume(ctx->vm, 0);
    return rc;
}


/**
 * ngx.sleep()超时后的handler
 */
static void
ngx_http_lua_test_sleep_handler(ngx_event_t *ev)
{
    ngx_http_request_t *r = ev->data;
    ngx_http_lua_test_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_test_module);

    ctx->resume_handler = ngx_http_lua_test_sleep_resume;
    //会导致ngx_http_test_handler回调函数的第二次调用
    ngx_http_core_run_phases(r);

    return;
}


/**
 * ngx.sleep(seconds)
 * 
 * Lua提供了两个C语言接口，lua_yield可以将一个协程挂起，lua_resume使协程恢复运行。要使协程休眠一段时间后再运行，可以通过下面的步骤实现。
    1.添加定时器，一段时间后执行回调函数
    2.调用lua_yield挂起协程
    3.在回调函数中调用lua_resume运行挂起的协程
 */
static int
ngx_http_lua_test_ngx_sleep(lua_State *L)
{
    ngx_int_t          delay = luaL_checkint(L, 1);
    ngx_http_request_t *r;

    lua_getglobal(L, ngx_http_lua_test_req_key);
    r = lua_touserdata(L, -1);

    ngx_event_t     *sleep = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
    //超时后执行
    sleep->handler = ngx_http_lua_test_sleep_handler;
    sleep->data = r;
    sleep->log = r->connection->log;

    ngx_add_timer(sleep, (ngx_msec_t) delay * 1000);

    return lua_yield(L, 0);
}

/**
 * ngx.get_method()
 */
static int
ngx_http_lua_test_ngx_get_method(lua_State *L)
{
    ngx_http_request_t *r;
    lua_getglobal(L, ngx_http_lua_test_req_key);
    r = lua_touserdata(L, -1);

    lua_pushlstring(L, (char *) r->method_name.data, r->method_name.len);

    return 1;
}

/**
 * 创建loc级别的配置
 */
static void *
ngx_http_lua_test_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_lua_test_loc_conf_t *conf = NULL;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_test_loc_conf_t));
    if (conf == NULL) return NULL;

    ngx_str_null(&conf->script);

    /* 初始化Lua环境 */
    /* 创建一个全局的global_State结构和代表一个协程的lua_State结构，lua_State作为主协程返回 */
    lua_State   *L = luaL_newstate();
    if (!L) return NULL;

    /*  将print, math，string,table等Lua内置的函数库注册到协程中 */
    luaL_openlibs(L);

    conf->vm = L;

    lua_pushlightuserdata(L, &ngx_http_lua_test_coroutines_key);
    lua_createtable(L, 0, 0);
    lua_rawset(L, LUA_REGISTRYINDEX);

    return conf;
}


/**
 * postconfiguration
 * 
 * 注册一个access阶段的handler
 */
static ngx_int_t
ngx_http_lua_test_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    /* 在ACCESS阶段挂在回调函数 */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    //ACCESS_PHASE handler 
    *h = ngx_http_lua_test_handler;

    return NGX_OK;
}

