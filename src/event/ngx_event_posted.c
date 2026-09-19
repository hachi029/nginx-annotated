
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ngx_queue_t  ngx_posted_accept_events;
ngx_queue_t  ngx_posted_next_events;
//由普通读/写事件构成的 ngx_posted_events队列.存放暂时不需要处理的事件
ngx_queue_t  ngx_posted_events;


/**
 * 执行posted队列中的事件，反复从事件队列中删除第一个元素，并调用元素的处理程序，直到队列为空为止
 */
void
ngx_event_process_posted(ngx_cycle_t *cycle, ngx_queue_t *posted)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    //遍历posted队列中的事件
    while (!ngx_queue_empty(posted)) {

        q = ngx_queue_head(posted);
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        //从posted队列中删除这个事件
        ngx_delete_posted_event(ev);

        //执行事件的回调方法
        ev->handler(ev);
    }
}


/**
 * 将ngx_posted_next_events队列中的事件移动到ngx_posted_events队列中
 * 这些事件会在下一次ngx_process_events方法中处理
 * 
 */
void
ngx_event_move_posted_next(ngx_cycle_t *cycle)
{
    ngx_queue_t  *q;
    ngx_event_t  *ev;

    for (q = ngx_queue_head(&ngx_posted_next_events);
         q != ngx_queue_sentinel(&ngx_posted_next_events);
         q = ngx_queue_next(q))
    {
        ev = ngx_queue_data(q, ngx_event_t, queue);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    ngx_queue_add(&ngx_posted_events, &ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_next_events);
}
