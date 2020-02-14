// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "app.h"

#define FUZZBUF_SZ 512
#define HIDMSG_SZ 64
#define STDIN 0
#define RK_NUM  50

const char * state_file = "authenticator_state.bin";
const char * rk_file = "resident_keys.bin";

struct ResidentKeyStore {
    CTAP_residentKey rks[RK_NUM];
} RK_STORE;


uint32_t millis() { return 0; }
void usbhid_send(uint8_t *msg) { return; }

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
        // printf("state file exists\n");
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

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    authenticator_initialize();
    ctaphid_init();
    ctap_init( 1 );
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    const uint8_t *data_end = Data + Size;

    for (uint8_t *pkt_raw=Data; pkt_raw<data_end; pkt_raw += HIDMSG_SZ) {
        ctaphid_handle_packet(pkt_raw);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    uint8_t fuzzbuf[FUZZBUF_SZ];


    set_logging_mask(
  		// TAG_GEN|
  		// TAG_MC |
  		// TAG_GA |
  		TAG_WALLET |
  		TAG_STOR |
  		//TAG_NFC_APDU |
  		TAG_NFC |
  		// TAG_CP |
  		// TAG_CTAP|
  		// TAG_HID|
  		TAG_U2F|
  		// TAG_PARSE |
  		//TAG_TIME|
  		// TAG_DUMP|
  		// TAG_DUMP2|
  		TAG_GREEN|
  		TAG_RED|
      TAG_EXT|
      TAG_CCID|
      TAG_ERR
	  );
    

    LLVMFuzzerInitialize(&argc, &argv);

    ssize_t bytes_read = read(STDIN, fuzzbuf, FUZZBUF_SZ);

    // Ignore last packet which may not be 64 bytes long
    bytes_read -= bytes_read % HIDMSG_SZ;

    LLVMFuzzerTestOneInput(fuzzbuf, bytes_read);

    return 0;
}
