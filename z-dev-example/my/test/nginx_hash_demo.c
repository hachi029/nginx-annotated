#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hash.h>
#include <ngx_log.h>
#include <stdio.h>

/**
 gcc -O0 -g -o nginx_hash_demo nginx_hash_demo.c \ 
-I/home/hachi/projects/nginx-anno/src/core -I/home/hachi/projects/nginx-anno/src/event \
-I/home/hachi/projects/nginx-anno/src/os/unix -I/home/hachi/projects/nginx-anno/objs \ 
-L/home/hachi/projects/nginx-anno/ -lnginx -lpthread -lpcre -lz -lcrypt
 */

int main() {
    // 初始化Nginx内存池
    ngx_pool_t *pool;
    ngx_log_t  *log;
    ngx_time_init();
    log = ngx_log_init("", "/dev/null");
    ngx_log_error(NGX_LOG_ALERT, log, 0, "key:\"%ui\"", "xx");
    ngx_cpuinfo();
    pool = ngx_create_pool(1024, log);
    if (pool == NULL) {
        fprintf(stderr, "创建内存池失败\n");
        return 1;
    }

    // 定义哈希表配置
    ngx_hash_init_t hash_init;
    ngx_hash_t hash;
    ngx_hash_key_t *keys;
    ngx_uint_t n = 3; // 键值对数量

    // 分配键数组内存
    keys = ngx_palloc(pool, n * sizeof(ngx_hash_key_t));
    if (keys == NULL) {
        fprintf(stderr, "无法分配键数组内存\n");
        ngx_destroy_pool(pool);
        return 1;
    }

    // 设置键值对
    // 键1: "name", 值: "nginx"
    keys[0].key.len = 4;
    keys[0].key.data = (u_char *)"name";
    keys[0].value = (void *)"nginx";
    
    // 键2: "version", 值: "1.21.0"
    keys[1].key.len = 7;
    keys[1].key.data = (u_char *)"version";
    keys[1].value = (void *)"1.21.0";
    
    // 键3: "author", 值: "Igor Sysoev"
    keys[2].key.len = 6;
    keys[2].key.data = (u_char *)"author";
    keys[2].value = (void *)"Igor Sysoev";

    // 初始化哈希表配置
    hash_init.hash = &hash;
    hash_init.key = ngx_hash_key_lc;
    hash_init.max_size = 1024;
    hash_init.bucket_size = 1024;
    hash_init.name =  (u_char *)"xxx";
    hash_init.pool = pool;
    hash_init.temp_pool = NULL;

    // 初始化哈希表
    if (ngx_hash_init(&hash_init, keys, n) != NGX_OK) {
        fprintf(stderr, "哈希表初始化失败\n");
        ngx_destroy_pool(pool);
        return 1;
    }

    // 查找哈希表中的键
    u_char *key = (u_char *)"author";

    ngx_uint_t keyhash = 0;
    ngx_uint_t i = 0;

    for (i = 0; i < ngx_strlen(key); i++) {
        keyhash = ngx_hash(keyhash, key[i]);
    }

    void *value = ngx_hash_find(&hash, keyhash, key, ngx_strlen(key));
    
    if (value != NULL) {
        printf("找到键 '%s'，值: %s\n", key, (char *)value);
    } else {
        printf("未找到键 '%s'\n", key);
    }

    // 释放内存池
    ngx_destroy_pool(pool);
    return 0;
}
