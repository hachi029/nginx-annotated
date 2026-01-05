
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_SCRIPT_H_INCLUDED_
#define _NGX_HTTP_SCRIPT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/**
 * 同一段脚本被编译进Nginx中，在不同的请求里执行时效果是完全不同的，
 * 所以，每一个请求都必须有其独有的脚本执行上下文，或者称为脚本引擎，这是最关键的数据结构
 */
typedef struct {
    // 指向待执行的脚本指令，始终指向下一行要执行的代码
    //指向的是实现了ngx_http_script_code_pt接口的类
    u_char                     *ip;
    u_char                     *pos;        //指向的是构建变量值的buf的当前位置，如[abc...] 指向的是第4个位置
     // 变量值构成的栈,栈大小默认为10个变量
    ngx_http_variable_value_t  *sp;

    ngx_str_t                   buf;
    ngx_str_t                   line;

    /* the start of the rewritten arguments */
    u_char                     *args;

    unsigned                    flushed:1;
    unsigned                    skip:1;
    unsigned                    quote:1;
    unsigned                    is_args:1;
    unsigned                    log:1;

    // 脚本引擎执行状态
    ngx_int_t                   status;
    // 指向当前脚本引擎所属的HTTP请求
    ngx_http_request_t         *request;
} ngx_http_script_engine_t;


/**
 * 编译复杂变量时，需传入此结构体
 */
typedef struct {
    ngx_conf_t                 *cf;
    ngx_str_t                  *source;     //复杂变量的原始值

    /*  保存需要刷新的变量下标，刷新r->variables数组。 */
    ngx_array_t               **flushes;    //指向每个元素为ngx_uint_t的动态数组
    /**
     * 因为nginx需要先计算整个复杂变量的总长度，然后才能分配足够的内存空间来依次存放每个变量值，得到最终的值。
     * （在计算长度的时候，就可能调用变量的get函数，该函数会计算出值，如果值是可缓存的，后续计算值的时候，就可以不再调用get方法了，以此可以提高效率）
     */
    ngx_array_t               **lengths;    //依次存的是计算变量长度的执行单元(code)
    ngx_array_t               **values;     //依次存在的是计算变量值的执行单元(code)

    ngx_uint_t                  variables;  //包含变量的个数($字符的个数)，两个用途，开始编译前是字符串$的个数，编译后是真实的变量的个数。正则表达式捕获设置别名的才会生成变量
    ngx_uint_t                  ncaptures;  //记录正则匹配捕获组的最大n, $0-$9 ,正则表达式匹配获取结果的个数 
    ngx_uint_t                  captures_mask; /*  正则表达式 标志变量重复 */
    ngx_uint_t                  size;   /*  常量字符串总长度，例如:A_${host}_B_${remorete_ip} 中A__B_为常量字符串。两个变量host和remote_ip*/

    void                       *main;

    unsigned                    compile_args:1;
    unsigned                    complete_lengths:1;  /* 是否要编译lengths数组，如果是，在该数组后添加个null */
    unsigned                    complete_values:1;  /* 是否需要添加null */
    unsigned                    zero:1;
    unsigned                    conf_prefix:1;
    unsigned                    root_prefix:1;

    unsigned                    dup_capture:1;  /*  正则表达式是否使用了重复的变量 */
    unsigned                    args:1;         //标识，是否含有？
} ngx_http_script_compile_t;


/**
 * 表示一个复杂变量（脚本），含有多个'$'的字符串
 * 需要在运行时计算。
 * 
 * 由ngx_http_compile_complex_value在配置阶段编译而来
 */
typedef struct {
    ngx_str_t                   value;      //解析出来的变量值

    //编译复杂变量的过程基本就是向三个数组（flushes、lengths、values）中添加回调和内容
    //执行是遍历其中的2个数组（lengths 、values）调用编译阶段添加的回调函数。
    ngx_uint_t                 *flushes;
    //用于计算变量值的长度
    //contains information about the presence of variables in the expression
    //The NULL value means that the expression contained static text only, and so can be stored in a simple string rather than as a complex value
    void                       *lengths;
    //用于计算变量值
    void                       *values;

    union {
        size_t                  size;
    } u;
} ngx_http_complex_value_t;


/**
 * The complex value description in ngx_http_compile_complex_value is compiled at the configuration stage 
 * into ngx_http_complex_value_t which is used at runtime to obtain results of expression evaluation.
 * 
 * 对字符串进行“编译”，之后才能正确得到变量值。
 * 
 * 因此需要通过这个结构体，才能获取到ngx_http_complex_value_t
 */ 
typedef struct {
    ngx_conf_t                 *cf;     // nginx的配置结构体指针 Configuration pointer
    ngx_str_t                  *value;  // 配置文件里的原始字符串 String to be parsed (input)
    ngx_http_complex_value_t   *complex_value;  // 编译后的输出结果，即复杂变量 Compiled value (output)

    //The zero flag is useful when results are to be passed to libraries that require zero-terminated strings, 
    //and prefixes are handy when dealing with filenames
    unsigned                    zero:1;         // Flag that enables zero-terminating value
    //Prefixes the result with the configuration prefix (the directory where nginx is currently looking for configuration)
    unsigned                    conf_prefix:1;      //标识值是nginx.conf配置文件所在目录的路径字符串
    //Prefixes the result with the root prefix (the normal nginx installation prefix)
    unsigned                    root_prefix:1;      //标识值是nginx.conf配置文件所在目录的路径字符串
} ngx_http_compile_complex_value_t;


//ngx_http_script_engine_t的ip指向的函数指针，相当于抽象基类的一个接口
//对于“set”配置来说，编译变量名（即第1个参数）由一个实现了ngx_http_script_code_pt
//接口的类担当，这个类实际上是由结构体ngx_http_script_var_code_t来承担的
//其实现有ngx_http_script_var_code_t/ngx_http_script_value_code_t
typedef void (*ngx_http_script_code_pt) (ngx_http_script_engine_t *e);
typedef size_t (*ngx_http_script_len_code_pt) (ngx_http_script_engine_t *e);


/**
 * xxx$yyy中处理xxx
 * 计算的是常量,len等于常量的字符串长度
 */
typedef struct {
    ngx_http_script_code_pt     code;   //执行函数(函数指针)
    uintptr_t                   len;    //值长度，变量值的长度
} ngx_http_script_copy_code_t;


/**
 * 获取普通变量执行的指令 $host
 */
//表示set指令中的变量名（第一个参数）
//对于“set”配置来说，编译变量名（即第1个参数）由一个实现了ngx_http_script_code_pt
//接口的类担当，这个类实际上是由结构体ngx_http_script_var_code_t来承担的
typedef struct {
    //在set imagewidth 100;例子中，code指向的脚本指令方法为 ngx_http_script_set_var_code
    ngx_http_script_code_pt     code;
    // 表示ngx_http_request_t中被索引、缓存的变量值数组variables中，当前解析的、
    // set设置的外部变量所在的索引号
    uintptr_t                   index;
} ngx_http_script_var_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    ngx_http_set_variable_pt    handler;        //ngx_http_script_var_set_handler_code
    uintptr_t                   data;
} ngx_http_script_var_handler_code_t;


//标识一个正则匹配组变量 如 $2
typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   n;      //n为捕获组索引
} ngx_http_script_copy_capture_code_t;


#if (NGX_PCRE)

//执行正则匹配的code, 
typedef struct {
    ngx_http_script_code_pt     code;       //指令执行函数
    ngx_http_regex_t           *regex;      //编译好的正则表达式
    ngx_array_t                *lengths;
    uintptr_t                   size;       /*  字符串常量长度，除去变量  */
    uintptr_t                   status;     //客户端响应状态码
    uintptr_t                   next;       //下一跳指令

    unsigned                    test:1;
    unsigned                    negative_test:1;        //标识是反向匹配 如 !~ !~*
    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;         //标识要添加原始args参数

    unsigned                    redirect:1;         //标识客户端重定向 redirect
    unsigned                    break_cycle:1;      //标识break, 是否跳出当前阶段

    ngx_str_t                   name;       //原始正则表达式
} ngx_http_script_regex_code_t;


typedef struct {
    ngx_http_script_code_pt     code;

    unsigned                    uri:1;
    unsigned                    args:1;

    /* add the r->args to the new arguments */
    unsigned                    add_args:1;

    unsigned                    redirect:1;
} ngx_http_script_regex_end_code_t;

#endif


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   conf_prefix;
} ngx_http_script_full_name_code_t;


/**
 * return 指令
 */
typedef struct {
    ngx_http_script_code_pt     code;       //执行函数 ngx_http_script_return_code
    uintptr_t                   status;     //返回状态码
    ngx_http_complex_value_t    text;       //返回文本，可以包含变量
} ngx_http_script_return_code_t;


typedef enum {
    ngx_http_script_file_plain = 0,
    ngx_http_script_file_not_plain,
    ngx_http_script_file_dir,
    ngx_http_script_file_not_dir,
    ngx_http_script_file_exists,
    ngx_http_script_file_not_exists,
    ngx_http_script_file_exec,
    ngx_http_script_file_not_exec
} ngx_http_script_file_op_e;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   op;
} ngx_http_script_file_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    uintptr_t                   next;
    void                      **loc_conf;
} ngx_http_script_if_code_t;


typedef struct {
    ngx_http_script_code_pt     code;
    ngx_array_t                *lengths;
} ngx_http_script_complex_value_code_t;


/**
 * 表示set 指令中的变量值（如果第二个参数是纯字符串值）
 */
typedef struct {
    // 在set imagewidth 100; 例子中，code指向的脚本指令方法为ngx_http_script_value_code
    ngx_http_script_code_pt     code;
     // 变量个数
    uintptr_t                   value;
    // 常量字符串长度
    uintptr_t                   text_len;
    // 常量字符串
    uintptr_t                   text_data;
} ngx_http_script_value_code_t;


void ngx_http_script_flush_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val);
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, ngx_str_t *value);
size_t ngx_http_complex_value_size(ngx_http_request_t *r,
    ngx_http_complex_value_t *val, size_t default_value);
ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv);
char *ngx_http_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_set_complex_value_zero_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_set_complex_value_size_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


ngx_int_t ngx_http_test_predicates(ngx_http_request_t *r,
    ngx_array_t *predicates);
ngx_int_t ngx_http_test_required_predicates(ngx_http_request_t *r,
    ngx_array_t *predicates);
char *ngx_http_set_predicate_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

ngx_uint_t ngx_http_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_http_script_compile(ngx_http_script_compile_t *sc);
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value,
    void *code_lengths, size_t reserved, void *code_values);
void ngx_http_script_flush_no_cacheable_variables(ngx_http_request_t *r,
    ngx_array_t *indices);

void *ngx_http_script_start_code(ngx_pool_t *pool, ngx_array_t **codes,
    size_t size);
void *ngx_http_script_add_code(ngx_array_t *codes, size_t size, void *code);

size_t ngx_http_script_copy_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_var_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_var_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e);
void ngx_http_script_copy_capture_code(ngx_http_script_engine_t *e);
size_t ngx_http_script_mark_args_code(ngx_http_script_engine_t *e);
void ngx_http_script_start_args_code(ngx_http_script_engine_t *e);
#if (NGX_PCRE)
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
void ngx_http_script_regex_end_code(ngx_http_script_engine_t *e);
#endif
void ngx_http_script_return_code(ngx_http_script_engine_t *e);
void ngx_http_script_break_code(ngx_http_script_engine_t *e);
void ngx_http_script_if_code(ngx_http_script_engine_t *e);
void ngx_http_script_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_not_equal_code(ngx_http_script_engine_t *e);
void ngx_http_script_file_code(ngx_http_script_engine_t *e);
void ngx_http_script_complex_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_value_code(ngx_http_script_engine_t *e);
void ngx_http_script_set_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_set_handler_code(ngx_http_script_engine_t *e);
void ngx_http_script_var_code(ngx_http_script_engine_t *e);
void ngx_http_script_nop_code(ngx_http_script_engine_t *e);


#endif /* _NGX_HTTP_SCRIPT_H_INCLUDED_ */
