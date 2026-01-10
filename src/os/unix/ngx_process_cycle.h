
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_CYCLE_H_INCLUDED_
#define _NGX_PROCESS_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/**
 * master与worker间通信的命令 参考ngx_channel_t
 */

 // 打开频道，使用频道这种方式通信前必须发送的命令
#define NGX_CMD_OPEN_CHANNEL   1
// 关闭已经打开的频道，实际上也就是关闭套接字
#define NGX_CMD_CLOSE_CHANNEL  2
// 要求接收方正常地退出进程
#define NGX_CMD_QUIT           3
// 要求接收方强制地结束进程
#define NGX_CMD_TERMINATE      4
// 要求接收方重新打开进程已经打开过的文件
#define NGX_CMD_REOPEN         5


//进程类型 https://nginx.org/en/docs/dev/development_guide.html#Processes

//The single process,  
//单进程模式，master_process off; 是此模式下唯一存在的进程。处理函数是ngx_single_process_cycle()
#define NGX_PROCESS_SINGLE     0
//master进程, 处理函数 ngx_master_process_cycle 
//The master process reads the NGINX configuration, creates cycles, and starts and controls child processes. It does not perform any I/O and responds only to signals
#define NGX_PROCESS_MASTER     1
//只是一个发送信号的进程. nginx -s stop
#define NGX_PROCESS_SIGNALLER  2
//worker进程, 处理函数 ngx_worker_process_cycle
//handles client connections
#define NGX_PROCESS_WORKER     3
//辅助进程. 如cache manager、cache loader等, 两者的处理函数是ngx_cache_manager_process_cycle()
#define NGX_PROCESS_HELPER     4


typedef struct {
    ngx_event_handler_pt       handler;
    char                      *name;
    ngx_msec_t                 delay;
} ngx_cache_manager_ctx_t;


void ngx_master_process_cycle(ngx_cycle_t *cycle);
void ngx_single_process_cycle(ngx_cycle_t *cycle);


extern ngx_uint_t      ngx_process;
extern ngx_uint_t      ngx_worker;
extern ngx_pid_t       ngx_pid;
extern ngx_pid_t       ngx_new_binary;
extern ngx_uint_t      ngx_inherited;
extern ngx_uint_t      ngx_daemonized;
extern ngx_uint_t      ngx_exiting;

extern sig_atomic_t    ngx_reap;
extern sig_atomic_t    ngx_sigio;
extern sig_atomic_t    ngx_sigalrm;
extern sig_atomic_t    ngx_quit;
extern sig_atomic_t    ngx_debug_quit;
extern sig_atomic_t    ngx_terminate;
extern sig_atomic_t    ngx_noaccept;
extern sig_atomic_t    ngx_reconfigure;
extern sig_atomic_t    ngx_reopen;
extern sig_atomic_t    ngx_change_binary;


#endif /* _NGX_PROCESS_CYCLE_H_INCLUDED_ */
