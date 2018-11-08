
#include "device.h"
#include "usbd_def.h"
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_tim.h"
#include "stm32l4xx_ll_usart.h"
#include "usbd_hid.h"

#include "app.h"
#include "flash.h"
#include "rng.h"
#include "led.h"
#include "device.h"
#include "util.h"
#include "fifo.h"
#include "log.h"
#include "ctaphid.h"


#define PAGE_SIZE		2048
#define PAGES			128
// Pages 119-127 are data
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)


#define APPLICATION_START_PAGE	(0)
#define APPLICATION_START_ADDR	flash_addr(APPLICATION_START_PAGE)

#define APPLICATION_END_PAGE	((PAGES - 9))					         // 119 is NOT included in application
#define APPLICATION_END_ADDR	(flash_addr(APPLICATION_END_PAGE)-4)     // NOT included in application

#define AUTH_WORD_ADDR          (flash_addr(APPLICATION_END_PAGE)-4)

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


void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
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

void usbhid_init()
{
    printf1(TAG_GEN,"hello solo\r\n");
}
int usbhid_recv(uint8_t * msg)
{
    if (fifo_hidmsg_size())
    {
        fifo_hidmsg_take(msg);
        printf1(TAG_DUMP,">> ");
        dump_hex1(TAG_DUMP,msg, HID_PACKET_SIZE);
        return HID_PACKET_SIZE;
    }
    return 0;
}

void usbhid_send(uint8_t * msg)
{

    printf1(TAG_DUMP,"<< ");
    dump_hex1(TAG_DUMP, msg, HID_PACKET_SIZE);
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


void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}
