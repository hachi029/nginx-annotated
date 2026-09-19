
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_POSTED_H_INCLUDED_
#define _NGX_EVENT_POSTED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/**
 * https://nginx.org/en/docs/dev/development_guide.html#posted_events
 * An event can be posted which means that its handler will be called at some point later within the current event loop iteration. 
 * Posting events is a good practice for simplifying code and escaping stack overflows. Posted events are held in a post queue.
 * 
 * The ngx_post_event(ev, q) macro posts the event ev to the post queue q
 * 
 * Normally, events are posted to the ngx_posted_events queue, which is processed late in the event loop — after all I/O and timer events are already handled.
 * The function ngx_event_process_posted() is called to process an event queue. It calls event handlers until the queue is empty. 
 * This means that a posted event handler can post more events to be processed within the current event loop iteration.
 * 
 */
/**
 * 将事件ev加入队列q队尾， ngx_event_process_posted()函数被调用以处理事件队列。它调用事件处理程序，直到队列不为空为止
 */
#define ngx_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        ngx_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }


/**
 * deletes the event ev from the queue it's currently posted in
 * 
 * 将事件ev从q中移除
 */
#define ngx_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    ngx_queue_remove(&(ev)->queue);                                           \
                                                                              \
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



void ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted);
void ngx_event_move_posted_next(ngx_cycle_t *cycle);


extern ngx_queue_t  ngx_posted_accept_events;
extern ngx_queue_t  ngx_posted_next_events;
extern ngx_queue_t  ngx_posted_events;


#endif /* _NGX_EVENT_POSTED_H_INCLUDED_ */
