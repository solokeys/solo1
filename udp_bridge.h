#ifndef _UDP_BRIDGE_H
#define _UDP_BRIDGE_H

int udp_server();

// Recv from anyone
void udp_recv(int fd, uint8_t * buf, int size);

// Send to 127.0.0.1:7112
void udp_send(int fd, uint8_t * buf, int size);

void udp_close(int fd);

#endif
