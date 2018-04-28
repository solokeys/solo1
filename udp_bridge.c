/*
 * Used as a bridge for USBHID protocol for FIDO 2.0 and U2F to ease firmware development and testing.
 *
 * Client FIDO 2.0, U2F software should bind to UDP port 7112 to send/recv USBHID messages from.
 *
 * */

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int udp_server()
{
    int fd;
    if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror( "socket failed" );
        return 1;
    }

    struct sockaddr_in serveraddr;
    memset( &serveraddr, 0, sizeof(serveraddr) );
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons( 8111 );
    serveraddr.sin_addr.s_addr = htonl( INADDR_ANY );

    if ( bind(fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror( "bind failed" );
        exit(1);
    }
    return fd;
}

void udp_recv(int fd, uint8_t * buf, int size)
{
    int length = recvfrom( fd, buf, size, 0, NULL, 0 );
    if ( length < 0 ) {
        perror( "recvfrom failed" );
        exit(1);
    }
}


void udp_send(int fd, uint8_t * buf, int size)
{
    struct sockaddr_in serveraddr;
    memset( &serveraddr, 0, sizeof(serveraddr) );
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons( 7112 );
    serveraddr.sin_addr.s_addr = htonl( 0x7f000001 ); // (127.0.0.1)

    if (sendto( fd, buf, size, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 ) {
        perror( "sendto failed" );
        exit(1);
    }
}

void udp_close(int fd)
{
    close(fd);
}


