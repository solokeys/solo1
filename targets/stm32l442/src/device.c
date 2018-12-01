
#include "device.h"
#include "usbd_def.h"
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_tim.h"
#include "stm32l4xx_ll_usart.h"
#include "usbd_hid.h"

#include APP_CONFIG
#include "flash.h"
#include "rng.h"
#include "led.h"
#include "device.h"
#include "util.h"
#include "fifo.h"
#include "log.h"
#include "ctaphid.h"
#include "ctap.h"
#include "crypto.h"
#include "uECC.h"


#define PAGE_SIZE		2048
#define PAGES			128
// Pages 119-127 are data
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)

#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)


#define APPLICATION_START_PAGE	(0)
#define APPLICATION_START_ADDR	flash_addr(APPLICATION_START_PAGE)

#define APPLICATION_END_PAGE	((PAGES - 19))					         // 119 is NOT included in application
#define APPLICATION_END_ADDR	(flash_addr(APPLICATION_END_PAGE)-8)     // NOT included in application

#define AUTH_WORD_ADDR          (flash_addr(APPLICATION_END_PAGE)-8)

uint32_t __90_ms = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
extern PCD_HandleTypeDef hpcd;

#define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))

// Timer6 overflow handler.  happens every ~90ms.
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __90_ms += 1;
    if ((millis() - __last_update) > 8)
    {
        if (__device_status != CTAPHID_STATUS_IDLE)
        {
            ctaphid_update_status(__device_status);
        }
    }
}

// Global USB interrupt handler
void USB_IRQHandler(void)
{
  HAL_PCD_IRQHandler(&hpcd);
}

uint32_t millis()
{
    return (((uint32_t)TIM6->CNT) + (__90_ms * 90));
}

void device_set_status(int status)
{
    __disable_irq();
    __last_update = millis();
    __enable_irq();

    if (status != CTAPHID_STATUS_IDLE && __device_status != status)
    {
        ctaphid_update_status(status);
    }
    __device_status = status;
}

int device_is_button_pressed()
{
    return IS_BUTTON_PRESSED();
}

void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
}
void device_reboot()
{

}
void device_init()
{
    hw_init();
    LL_GPIO_SetPinMode(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_MODE_INPUT);
    LL_GPIO_SetPinPull(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_PULL_UP);

#if BOOT_TO_DFU
    flash_option_bytes_init(1);
#else
    flash_option_bytes_init(0);
#endif

    printf1(TAG_GEN,"hello solo\r\n");
}

void usb_init(void);
void usbhid_init()
{
    usb_init();
    printf1(TAG_GEN,"hello solo\r\n");
}
int usbhid_recv(uint8_t * msg)
{
    if (fifo_hidmsg_size())
    {
        fifo_hidmsg_take(msg);
        printf1(TAG_DUMP2,">> ");
        dump_hex1(TAG_DUMP2,msg, HID_PACKET_SIZE);
        return HID_PACKET_SIZE;
    }
    return 0;
}

void usbhid_send(uint8_t * msg)
{

    printf1(TAG_DUMP2,"<< ");
    dump_hex1(TAG_DUMP2, msg, HID_PACKET_SIZE);
    while (PCD_GET_EP_TX_STATUS(USB, HID_EPIN_ADDR & 0x0f) == USB_EP_TX_VALID)
        ;
    USBD_LL_Transmit(&Solo_USBD_Device, HID_EPIN_ADDR, msg, HID_PACKET_SIZE);


}

void ctaphid_write_block(uint8_t * data)
{
    usbhid_send(data);
}


void usbhid_close()
{

}

void main_loop_delay()
{

}

void heartbeat()
{
    static int state = 0;
    static uint32_t val = (LED_INIT_VALUE >> 8) & 0xff;
    int but = IS_BUTTON_PRESSED();

    if (state)
    {
        val--;
    }
    else
    {
        val++;
    }

    if (val > 30 || val < 1)
    {
        state = !state;
    }
    if (but) led_rgb(val * 2);
    else
        led_rgb((val << 16) | (val*2 << 8));
}

void authenticator_read_state(AuthenticatorState * a)
{
    uint32_t * ptr = (uint32_t *)flash_addr(STATE1_PAGE);
    memmove(a,ptr,sizeof(AuthenticatorState));
}

void authenticator_read_backup_state(AuthenticatorState * a)
{
    uint32_t * ptr = (uint32_t *)flash_addr(STATE2_PAGE);
    memmove(a,ptr,sizeof(AuthenticatorState));
}

// Return 1 yes backup is init'd, else 0
int authenticator_is_backup_initialized()
{
    uint8_t header[16];
    uint32_t * ptr = (uint32_t *)flash_addr(STATE2_PAGE);
    memmove(header,ptr,16);
    AuthenticatorState * state = (AuthenticatorState*)header;
    return state->is_initialized == INITIALIZED_MARKER;
}

void authenticator_write_state(AuthenticatorState * a, int backup)
{
    if (! backup)
    {
        flash_erase_page(STATE1_PAGE);

        flash_write(flash_addr(STATE1_PAGE), (uint8_t*)a, sizeof(AuthenticatorState));
    }
    else
    {
        flash_erase_page(STATE2_PAGE);

        flash_write(flash_addr(STATE2_PAGE), (uint8_t*)a, sizeof(AuthenticatorState));
    }
}

uint32_t ctap_atomic_count(int sel)
{
    int offset = 0;
    uint32_t * ptr = (uint32_t *)flash_addr(COUNTER1_PAGE);
    uint32_t erases = *(uint32_t *)flash_addr(COUNTER2_PAGE);
    static uint32_t sc = 0;
    if (erases == 0xffffffff)
    {
        erases = 1;
        flash_erase_page(COUNTER2_PAGE);
        flash_write(flash_addr(COUNTER2_PAGE), (uint8_t*)&erases, 4);
    }

    uint32_t lastc = 0;

    if (sel != 0)
    {
        printf2(TAG_ERR,"counter2 not imple\n");
        exit(1);
    }

    for (offset = 0; offset < PAGE_SIZE/4; offset += 2) // wear-level the flash
    {
        if (ptr[offset] != 0xffffffff)
        {
            if (ptr[offset] < lastc)
            {
                printf2(TAG_ERR,"Error, count went down!\r\n");
            }
            lastc = ptr[offset];
        }
        else
        {
            break;
        }
    }

    if (!lastc) // Happens on initialization as well.
    {
        printf2(TAG_ERR,"warning, power interrupted during previous count.  Restoring. lastc==%lu, erases=%lu, offset=%d\r\n", lastc,erases,offset);
        // there are 32 counts per page
        lastc =  erases * 256 + 1;
        flash_erase_page(COUNTER1_PAGE);
        flash_write(flash_addr(COUNTER1_PAGE), (uint8_t*)&lastc, 4);

        erases++;
        flash_erase_page(COUNTER2_PAGE);
        flash_write(flash_addr(COUNTER2_PAGE), (uint8_t*)&erases, 4);
        return lastc;
    }

    lastc++;

    if (lastc/256 > erases)
    {
        printf2(TAG_ERR,"warning, power interrupted, erases mark, restoring. lastc==%lu, erases=%lu\r\n", lastc,erases);
        erases = lastc/256;
        flash_erase_page(COUNTER2_PAGE);
        flash_write(flash_addr(COUNTER2_PAGE), (uint8_t*)&erases, 4);
    }

    if (offset == PAGE_SIZE/4)
    {
        if (lastc/256 > erases)
        {
            printf2(TAG_ERR,"warning, power interrupted, erases mark, restoring lastc==%lu, erases=%lu\r\n", lastc,erases);
        }
        erases = lastc/256 + 1;
        flash_erase_page(COUNTER2_PAGE);
        flash_write(flash_addr(COUNTER2_PAGE), (uint8_t*)&erases, 4);

        flash_erase_page(COUNTER1_PAGE);
        offset = 0;
    }


    flash_write(flash_addr(COUNTER1_PAGE) + offset * 4, (uint8_t*)&lastc, 4);

    if (lastc == sc)
    {
        printf1(TAG_RED,"no count detected:  lastc==%lu, erases=%lu, offset=%d\r\n", lastc,erases,offset);
        while(1)
            ;
    }

    sc = lastc;

    return lastc;
}


void device_manage()
{
#if NON_BLOCK_PRINTING
    int i = 10;
    uint8_t c;
    while (i--)
    {
        if (fifo_debug_size())
        {
            fifo_debug_take(&c);
            while (! LL_USART_IsActiveFlag_TXE(DEBUG_UART))
                ;
            LL_USART_TransmitData8(DEBUG_UART,c);
        }
        else
        {
            break;
        }
    }
#endif
}

static int handle_packets()
{
    static uint8_t hidmsg[HID_PACKET_SIZE];
    memset(hidmsg,0, sizeof(hidmsg));
    if (usbhid_recv(hidmsg) > 0)
    {
        if ( ctaphid_handle_packet(hidmsg) ==  CTAPHID_CANCEL)
        {
            printf1(TAG_GREEN, "CANCEL!\r\n");
            return -1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

int ctap_user_presence_test()
{
    int ret;
#if SKIP_BUTTON_CHECK_WITH_DELAY
    int i=500;
    while(i--)
    {
        delay(1);
        ret = handle_packets();
        if (ret) return ret;
    }
    goto done;
#elif SKIP_BUTTON_CHECK_FAST
    delay(2);
    ret = handle_packets();
    if (ret) return ret;
    goto done;
#endif
    uint32_t t1 = millis();
    led_rgb(0xff3520);

while (IS_BUTTON_PRESSED())
{
    if (t1 + 5000 < millis())
    {
        printf1(TAG_GEN,"Button not pressed\n");
        goto fail;
    }
    ret = handle_packets();
    if (ret) return ret;
}

t1 = millis();

do
{
    if (t1 + 5000 < millis())
    {
        goto fail;
    }
    delay(1);
    ret = handle_packets();
    if (ret) return ret;
}
while (! IS_BUTTON_PRESSED());

led_rgb(0x001040);

delay(50);

done:
return 1;

fail:
return 0;
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    rng_get_bytes(dst, num);
    return 1;
}


int ctap_user_verification(uint8_t arg)
{
    return 1;
}

void ctap_reset_rk()
{
    int i;
    printf1(TAG_GREEN, "resetting RK \r\n");
    for(i = 0; i < RK_NUM_PAGES; i++)
    {
        flash_erase_page(RK_START_PAGE + i);
    }
}

uint32_t ctap_rk_size()
{
    return RK_NUM_PAGES * (PAGE_SIZE / sizeof(CTAP_residentKey));
}

void ctap_store_rk(int index,CTAP_residentKey * rk)
{
    int page_offset = (sizeof(CTAP_residentKey) * index) / PAGE_SIZE;
    uint32_t addr = flash_addr(page_offset + RK_START_PAGE) + ((sizeof(CTAP_residentKey)*index) % PAGE_SIZE);

    printf1(TAG_GREEN, "storing RK %d @ %04x\r\n", index,addr);

    if (page_offset < RK_NUM_PAGES)
    {
        flash_write(addr, (uint8_t*)rk, sizeof(CTAP_residentKey));
        //dump_hex1(TAG_GREEN,rk,sizeof(CTAP_residentKey));
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
}

void ctap_load_rk(int index,CTAP_residentKey * rk)
{
    int page_offset = (sizeof(CTAP_residentKey) * index) / PAGE_SIZE;
    uint32_t addr = flash_addr(page_offset + RK_START_PAGE) + ((sizeof(CTAP_residentKey)*index) % PAGE_SIZE);

    printf1(TAG_GREEN, "reading RK %d @ %04x\r\n", index, addr);
    if (page_offset < RK_NUM_PAGES)
    {
        uint32_t * ptr = (uint32_t *)addr;
        memmove((uint8_t*)rk,ptr,sizeof(CTAP_residentKey));
        //dump_hex1(TAG_GREEN,rk,sizeof(CTAP_residentKey));
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
}

void ctap_overwrite_rk(int index,CTAP_residentKey * rk)
{
    uint8_t tmppage[PAGE_SIZE];
    int page_offset = (sizeof(CTAP_residentKey) * index) / PAGE_SIZE;
    int page = page_offset + RK_START_PAGE;

    printf1(TAG_GREEN, "overwriting RK %d\r\n", index);
    if (page_offset < RK_NUM_PAGES)
    {
        memmove(tmppage, (uint8_t*)flash_addr(page), PAGE_SIZE);

        memmove(tmppage + (sizeof(CTAP_residentKey) * index) % PAGE_SIZE, rk, sizeof(CTAP_residentKey));
        flash_erase_page(page);
        flash_write(flash_addr(page), tmppage, ((sizeof(CTAP_residentKey) * (index + 1)) % PAGE_SIZE) );
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
}



void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}


#ifdef IS_BOOTLOADER

extern uint8_t REBOOT_FLAG;

typedef enum
{
    BootWrite = 0x40,
    BootDone = 0x41,
    BootCheck = 0x42,
    BootErase = 0x43,
} WalletOperation;


typedef struct {
    uint8_t op;
    uint8_t addr[3];
    uint8_t tag[4];
    uint8_t len;
    uint8_t payload[255 - 9];
} __attribute__((packed)) BootloaderReq;

//#define APPLICATION_START_ADDR	0x8000
//#define APPLICATION_START_PAGE	(0x8000/PAGE_SIZE)

//#define APPLICATION_END_ADDR	(PAGE_SIZE*125-4)		// NOT included in application

static void erase_application()
{
    int page;
    for(page = APPLICATION_START_PAGE; page < APPLICATION_END_PAGE; page++)
    {
        flash_erase_page(page);
    }
}

static void authorize_application()
{
    uint32_t zero = 0;
    uint32_t * ptr;
    ptr = (uint32_t *)AUTH_WORD_ADDR;
    flash_write((uint32_t)ptr, (uint8_t *)&zero, 4);
}
int is_authorized_to_boot()
{
    uint32_t * auth = (uint32_t *)AUTH_WORD_ADDR;
    return *auth == 0;
}

int bootloader_bridge(uint8_t klen, uint8_t * keyh)
{
    static int has_erased = 0;
    BootloaderReq * req =  (BootloaderReq *  )keyh;
    uint8_t payload[256];
    uint8_t hash[32];
    uint8_t * pubkey = (uint8_t*)"\x57\xe6\x80\x39\x56\x46\x2f\x0c\x95\xac\x72\x71\xf0\xbc\xe8\x2d\x67\xd0\x59\x29\x2e\x15\x22\x89\x6a\xbd\x3f\x7f\x27\xf3\xc0\xc6\xe2\xd7\x7d\x8a\x9f\xcc\x53\xc5\x91\xb2\x0c\x9c\x3b\x4e\xa4\x87\x31\x67\xb4\xa9\x4b\x0e\x8d\x06\x67\xd8\xc5\xef\x2c\x50\x4a\x55";
    const struct uECC_Curve_t * curve = NULL;

    if (req->len > 255-9)
    {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    memset(payload, 0xff, sizeof(payload));
    memmove(payload, req->payload, req->len);

    uint32_t addr = (*((uint32_t*)req->addr)) & 0xffffff;

    uint32_t * ptr = (uint32_t *)addr;

    switch(req->op){
        case BootWrite:
            if ((uint32_t)ptr < APPLICATION_START_ADDR || (uint32_t)ptr >= APPLICATION_END_ADDR)
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }

            if (!has_erased)
            {
                erase_application();
                has_erased = 1;
            }
            if (is_authorized_to_boot())
            {
                printf2(TAG_ERR, "Error, boot check bypassed\n");
                exit(1);
            }
            flash_write((uint32_t)ptr,payload, req->len + (req->len%4));
            break;
        case BootDone:
            ptr = (uint32_t *)APPLICATION_START_ADDR;
            crypto_sha256_init();
            crypto_sha256_update(ptr, APPLICATION_END_ADDR-APPLICATION_START_ADDR);
            crypto_sha256_final(hash);
            curve = uECC_secp256r1();

            if (! uECC_verify(pubkey,
                        hash,
                        32,
                        payload,
                        curve))
            {
                return CTAP2_ERR_OPERATION_DENIED;
            }
            authorize_application();
            REBOOT_FLAG = 1;
            break;
        case BootCheck:
            return 0;
            break;
        case BootErase:
            erase_application();
            return 0;
            break;
        default:
            return CTAP1_ERR_INVALID_COMMAND;
    }
    return 0;
}

void bootloader_heartbeat()
{
    static int state = 0;
    static uint32_t val = 0x10;
    int but = IS_BUTTON_PRESSED();

    if (state)
    {
        val--;
    }
    else
    {
        val++;
    }

    if (val > 30 || val < 1)
    {
        state = !state;
    }
    led_rgb((val * 3)<<8 | (val*10) << 16);
}

#endif
