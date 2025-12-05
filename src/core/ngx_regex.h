
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_REGEX_H_INCLUDED_
#define _NGX_REGEX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_PCRE2)

#define PCRE2_CODE_UNIT_WIDTH  8
#include <pcre2.h>

#define NGX_REGEX_NO_MATCHED   PCRE2_ERROR_NOMATCH   /* -1 */

typedef pcre2_code  ngx_regex_t;

#else

#include <pcre.h>

#define NGX_REGEX_NO_MATCHED   PCRE_ERROR_NOMATCH    /* -1 */

typedef struct {
    pcre        *code;
    pcre_extra  *extra;
} ngx_regex_t;

#endif


#define NGX_REGEX_CASELESS     0x00000001       //正则忽略大小写
#define NGX_REGEX_MULTILINE    0x00000002


/**
 * 正则表达式编译时的传参，参考 ngx_http_regex_compile
 */
typedef struct {
    ngx_str_t     pattern;      // 原始正则表达式
    ngx_pool_t   *pool;         /* 编译正则表达式从哪分配内存 */
    ngx_uint_t    options;      //编译选项，如 NGX_REGEX_CASELESS

    ngx_regex_t  *regex;        /* regex->code 编译后的结果，即pcre_compile返回 */
    int           captures;     /* pcre_fullinfo PCRE_INFO_CAPTURECOUNT 的值。捕获变量的个数 */
    int           named_captures;   /* 捕获变量设置了别名的个数 */
    int           name_size;    /* 捕获变量结构长度 */
    u_char       *names;        /* 捕获变量别名结构数组。别名下标占2个字节剩下的就是变量的名字。index=2*(x[0]<<8 + x[1])*/
    ngx_str_t     err;
} ngx_regex_compile_t;


typedef struct {
    ngx_regex_t  *regex;        //调用ngx_regex_compile后的编译结果. ngx_regex_compile_t->regex
    u_char       *name;         //原始正则字符串
} ngx_regex_elt_t;


void ngx_regex_init(void);
/**
 * 编译一个正则表达式，编译结果为 rc->regex
 */
ngx_int_t ngx_regex_compile(ngx_regex_compile_t *rc);

ngx_int_t ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures,
    ngx_uint_t size);

#if (NGX_PCRE2)
#define ngx_regex_exec_n       "pcre2_match()"
#else
#define ngx_regex_exec_n       "pcre_exec()"
#endif

ngx_int_t ngx_regex_exec_array(ngx_array_t *a, ngx_str_t *s, ngx_log_t *log);


#endif /* _NGX_REGEX_H_INCLUDED_ */
