#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "device.h"
#include "cbor.h"
#include "util.h"
#include "log.h"


void authenticator_initialize();

int udp_server()
{
    int fd;
    if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror( "socket failed" );
        return 1;
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(struct timeval)) != 0)
    {
        perror( "setsockopt" );
        exit(1);
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

int udp_recv(int fd, uint8_t * buf, int size)
{

    fd_set         input;
    FD_ZERO(&input);
    FD_SET(fd, &input);
    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = 100;
    int n = select(fd + 1, &input, NULL, NULL, &timeout);
    if (n == -1) {
        perror("select\n");
        exit(1);
    } else if (n == 0)
        return 0;
    if (!FD_ISSET(fd, &input))
    {

    }
    int length = recvfrom( fd, buf, size, 0, NULL, 0 );
    if ( length < 0 ) {
        perror( "recvfrom failed" );
        exit(1);
    }
    return length;
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



uint32_t millis()
{
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    uint64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
    return (uint32_t)milliseconds;
}


static int serverfd = 0;

void usbhid_init()
{
    // just bridge to UDP for now for pure software testing
    serverfd = udp_server();
}

// Receive 64 byte USB HID message, don't block, return size of packet, return 0 if nothing
int usbhid_recv(uint8_t * msg)
{
    int l = udp_recv(serverfd, msg, HID_MESSAGE_SIZE);
    /*if (l && l != HID_MESSAGE_SIZE)*/
    /*{*/
        /*printf("Error, recv'd message of wrong size %d", l);*/
        /*exit(1);*/
    /*}*/
    return l;
}

// Send 64 byte USB HID message
void usbhid_send(uint8_t * msg)
{
    udp_send(serverfd, msg, HID_MESSAGE_SIZE);
}

void usbhid_close()
{
    udp_close(serverfd);
}

void int_handler(int i)
{
    usbhid_close();
    printf("SIGINT... exiting.\n");
    exit(0);
}

void device_init()
{
    signal(SIGINT, int_handler);

    usbhid_init();

    authenticator_initialize();
}


void main_loop_delay()
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000*1000*25;
    nanosleep(&ts,NULL);
}


void heartbeat()
{

}

void ctaphid_write_block(uint8_t * data)
{
    /*printf("<< "); dump_hex(data, 64);*/
    usbhid_send(data);
}


int ctap_user_presence_test()
{
    return 1;
}

int ctap_user_verification(uint8_t arg)
{
    return 1;
}


uint32_t ctap_atomic_count(int sel)
{
    static uint32_t counter1 = 25;
    /*return 713;*/
    if (sel == 0)
    {
        printf1(TAG_RED,"counter1: %d\n", counter1);
        return counter1++;
    }
    else
    {
        printf2(TAG_ERR,"counter2 not imple\n");
        exit(1);
    }
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    int ret;
    FILE * urand = fopen("/dev/urandom","r");
    if (urand == NULL)
    {
        perror("fopen");
        exit(1);
    }
    ret = fread(dst, 1, num, urand);
    fclose(urand);

    if (ret != num)
    {
        perror("fwrite");
        exit(1);
    }
    /*memset(dst,0xaa,num);*/

    return 1;
}


const char * state_file = "authenticator_state.bin";
const char * backup_file = "authenticator_state2.bin";

void authenticator_read_state(AuthenticatorState * state)
{
    FILE * f;
    int ret;

    f = fopen(state_file, "rb");
    if (f== NULL)
    {
        perror("fopen");
        exit(1);
    }

    ret = fread(state, 1, sizeof(AuthenticatorState), f);
    fclose(f);
    if(ret != sizeof(AuthenticatorState))
    {
        perror("fwrite");
        exit(1);
    }

}

void authenticator_read_backup_state(AuthenticatorState * state )
{
    FILE * f;
    int ret;

    f = fopen(backup_file, "rb");
    if (f== NULL)
    {
        perror("fopen");
        exit(1);
    }

    ret = fread(state, 1, sizeof(AuthenticatorState), f);
    fclose(f);
    if(ret != sizeof(AuthenticatorState))
    {
        perror("fwrite");
        exit(1);
    }
}

void authenticator_write_state(AuthenticatorState * state, int backup)
{
    FILE * f;
    int ret;

    if (! backup)
    {
        f = fopen(state_file, "wb+");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }
        ret = fwrite(state, 1, sizeof(AuthenticatorState), f);
        fclose(f);
        if (ret != sizeof(AuthenticatorState))
        {
            perror("fwrite");
            exit(1);
        }
    }
    else
    {

        f = fopen(backup_file, "wb+");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }
        ret = fwrite(state, 1, sizeof(AuthenticatorState), f);
        fclose(f);
        if (ret != sizeof(AuthenticatorState))
        {
            perror("fwrite");
            exit(1);
        }
    }
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized()
{
    uint8_t header[16];
    AuthenticatorState * state = (AuthenticatorState*) header;
    FILE * f;
    int ret;

    printf("state file exists\n");
    f = fopen(backup_file, "rb");
    if (f== NULL)
    {
        printf("Warning, backup file doesn't exist\n");
        return 0;
    }

    ret = fread(header, 1, sizeof(header), f);
    fclose(f);
    if(ret != sizeof(header))
    {
        perror("fwrite");
        exit(1);
    }

    return state->is_initialized == INITIALIZED_MARKER;

}

// Return 1 yes backup is init'd, else 0
/*int authenticator_is_initialized()*/
/*{*/


/*}*/

void authenticator_initialize()
{
    uint8_t header[16];
    FILE * f;
    int ret;
    uint8_t * mem;
    if (access(state_file, F_OK) != -1)
    {
        printf("state file exists\n");
        f = fopen(state_file, "rb");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }

        ret = fread(header, 1, sizeof(header), f);
        fclose(f);
        if(ret != sizeof(header))
        {
            perror("fwrite");
            exit(1);
        }
    }
    else
    {
        printf("state file does not exist, creating it\n");
        f = fopen(state_file, "wb+");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }
        mem = malloc(sizeof(AuthenticatorState));
        memset(mem,0xff,sizeof(AuthenticatorState));
        ret = fwrite(mem, 1, sizeof(AuthenticatorState), f);
        free(mem);
        fclose(f);
        if (ret != sizeof(AuthenticatorState))
        {
            perror("fwrite");
            exit(1);
        }

        f = fopen(backup_file, "wb+");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }
        mem = malloc(sizeof(AuthenticatorState));
        memset(mem,0xff,sizeof(AuthenticatorState));
        ret = fwrite(mem, 1, sizeof(AuthenticatorState), f);
        free(mem);
        fclose(f);
        if (ret != sizeof(AuthenticatorState))
        {
            perror("fwrite");
            exit(1);
        }

    }
}

void manage_device()
{
    
}
