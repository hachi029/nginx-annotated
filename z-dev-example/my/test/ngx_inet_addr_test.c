#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

/* 假设这里包含了 ngx_inet_addr 的声明 */
extern in_addr_t ngx_inet_addr(u_char *text, size_t len);

int main() {
    u_char ip_text[] = "192.168.1.1";
    in_addr_t ip_addr;

    ip_addr = ngx_inet_addr(ip_text, sizeof(ip_text) - 1);
    if (ip_addr == (in_addr_t) -1) {
        printf("地址转换失败\n");
        return 1;
    }

    /* 转换为点分十进制格式输出（验证结果） */
    struct in_addr addr;
    addr.s_addr = ip_addr;
    printf("转换后的地址（网络字节序）: 0x%08X\n", ip_addr);
    printf("点分十进制格式: %s\n", inet_ntoa(addr));

    return 0;
}