// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "device.h"
#include "cbor.h"
#include "util.h"
#include "log.h"
#include "ctaphid.h"

#define RK_NUM  50

static bool use_udp = true;

struct ResidentKeyStore {
    CTAP_residentKey rks[RK_NUM];
} RK_STORE;

void authenticator_initialize();


int udp_server()
{
    static bool run_already = false;
    static int fd = -1;
    if (run_already && fd >= 0) return fd;
    run_already = true;

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
    printf1(TAG_DUMP, ">>"); dump_hex1(TAG_DUMP, buf, length);
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

    printf1(TAG_DUMP, "<<"); dump_hex1(TAG_DUMP, buf, size);
}


uint32_t millis()
{
    struct timeval te;
    gettimeofday(&te, NULL); // get current time
    uint64_t milliseconds = te.tv_sec*1000LL + te.tv_usec/1000; // calculate milliseconds
    return (uint32_t)milliseconds;
}


static int fd = 0;

void usbhid_init()
{
    if (use_udp)
    {
        fd = udp_server();
    }
    else
    {
        fd = open("/dev/hidg0", O_RDWR);
        if (fd < 0)
        {
            perror("hidg open");
            exit(1);
        }
    }
}

// Receive 64 byte USB HID message, don't block, return size of packet, return 0 if nothing
int usbhid_recv(uint8_t * msg)
{
    int l = 0;
    if (use_udp)
    {
        l = udp_recv(fd, msg, HID_MESSAGE_SIZE);
    }
    else
    {
        l = read(fd, msg, HID_MESSAGE_SIZE); /* Flawfinder: ignore */
        if (l < 0)
        {
            perror("hidg read");
            exit(1);
        }
    }
    uint8_t magic_cmd[] = "\xac\x10\x52\xca\x95\xe5\x69\xde\x69\xe0\x2e\xbf"
                          "\xf3\x33\x48\x5f\x13\xf9\xb2\xda\x34\xc5\xa8\xa3"
                          "\x40\x52\x66\x97\xa9\xab\x2e\x0b\x39\x4d\x8d\x04"
                          "\x97\x3c\x13\x40\x05\xbe\x1a\x01\x40\xbf\xf6\x04"
                          "\x5b\xb2\x6e\xb7\x7a\x73\xea\xa4\x78\x13\xf6\xb4"
                          "\x9a\x72\x50\xdc";
    if ( memcmp(magic_cmd, msg, 64) == 0 )
    {
        printf1(TAG_RED, "MAGIC REBOOT command recieved!\r\n");
        memset(msg,0,64);
        exit(100);
        return 0;
    }

    return l;
}

void usbhid_send(uint8_t * msg)
{
    if (use_udp)
    {
        udp_send(fd, msg, HID_MESSAGE_SIZE);
    }
    else
    {
        if (write(fd, msg, HID_MESSAGE_SIZE) < 0)
        {
            perror("hidg write");
            exit(1);
        }
    }
}



void usbhid_close()
{
    close(fd);
}

void int_handler(int i)
{
    usbhid_close();
    printf("SIGINT... exiting.\n");
    exit(0);
}



void usage(const char * cmd)
{
    fprintf(stderr, "Usage: %s [-b udp|hidg]\n", cmd);
    fprintf(stderr, "   -b      backing implementation: udp(default) or hidg\n");
    exit(1);
}

void device_init(int argc, char *argv[])
{

    int opt;

    while ((opt = getopt(argc, argv, "b:")) != -1)
    {
        switch (opt)
        {
            case 'b':
                if (strcmp("udp", optarg) == 0)
                {
                    use_udp = true;
                }
                else if (strcmp("hidg", optarg) == 0)
                {
                    use_udp = false;
                }
                else
                {
                    usage(argv[0]);
                }
                break;
            default:
                usage(argv[0]);
                break;
        }
    }

    signal(SIGINT, int_handler);

    printf1(TAG_GREEN, "Using %s backing\n", use_udp ? "UDP" : "hidg");
    usbhid_init();

    authenticator_initialize();

    ctaphid_init();

    ctap_init( 1 );
}


void delay(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000*1000*ms;
    nanosleep(&ts,NULL);
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
    if (fread(dst, 1, num, urand) != num)
    {
        perror("fread");
    }

    fclose(urand);

    return 1;
}


const char * state_file = "authenticator_state.bin";
const char * rk_file = "resident_keys.bin";

int authenticator_read_state(AuthenticatorState * state)
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
    if (state->is_initialized == INITIALIZED_MARKER)
        return 1;
    else
        return 0;
    
}


void authenticator_write_state(AuthenticatorState * state)
{
    FILE * f;
    int ret;

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


static void sync_rk()
{
    FILE * f = fopen(rk_file, "wb+");
    if (f== NULL)
    {
        perror("fopen");
        exit(1);
    }

    int ret = fwrite(&RK_STORE, 1, sizeof(RK_STORE), f);
    fclose(f);
    if (ret != sizeof(RK_STORE))
    {
        perror("fwrite");
        exit(1);
    }
}

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

        // resident_keys
        f = fopen(rk_file, "rb");
        if (f== NULL)
        {
            perror("fopen");
            exit(1);
        }
        ret = fread(&RK_STORE, 1, sizeof(RK_STORE), f);
        fclose(f);
        if(ret != sizeof(RK_STORE))
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

        // resident_keys
        memset(&RK_STORE,0xff,sizeof(RK_STORE));
        sync_rk();

    }
}


void ctap_reset_rk()
{
    memset(&RK_STORE,0xff,sizeof(RK_STORE));
    sync_rk();
}

uint32_t ctap_rk_size()
{
    return RK_NUM;
}


void ctap_store_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
        sync_rk();
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }

}

void ctap_delete_rk(int index)
{
    CTAP_residentKey rk;
    memset(&rk, 0xff, sizeof(CTAP_residentKey));
    memmove(RK_STORE.rks + index, &rk, sizeof(CTAP_residentKey));
}

void ctap_load_rk(int index, CTAP_residentKey * rk)
{
    memmove(rk, RK_STORE.rks + index, sizeof(CTAP_residentKey));
}

void ctap_overwrite_rk(int index, CTAP_residentKey * rk)
{
    if (index < RK_NUM)
    {
        memmove(RK_STORE.rks + index, rk, sizeof(CTAP_residentKey));
        sync_rk();
    }
    else
    {
        printf1(TAG_ERR,"Out of bounds for store_rk\r\n");
    }
}







