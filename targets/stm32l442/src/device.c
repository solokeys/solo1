
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


#define PAGE_SIZE		2048
#define PAGES			128
// Pages 120-127 are data
#define	COUNTER_PAGE	(PAGES - 3)
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)


#define APPLICATION_START_PAGE	(0)
#define APPLICATION_START_ADDR	flash_addr(APPLICATION_START_PAGE)

#define APPLICATION_END_PAGE	((PAGES - 8))					         // 120 is NOT included in application
#define APPLICATION_END_ADDR	(flash_addr(APPLICATION_END_PAGE)-4)     // NOT included in application

#define AUTH_WORD_ADDR          (flash_addr(APPLICATION_END_PAGE)-4)

uint32_t __65_seconds = 0;
extern PCD_HandleTypeDef hpcd;

#define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))

// Timer6 overflow handler
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __65_seconds += 1;
}
// Global USB interrupt handler
void USB_IRQHandler(void)
{
  HAL_PCD_IRQHandler(&hpcd);
}


uint32_t millis()
{
    return (((uint32_t)TIM6->CNT) | (__65_seconds<<16));
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
    uint32_t * ptr;
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
    uint32_t count;
    uint32_t zero = 0;
    uint32_t * ptr = (uint32_t *)flash_addr(COUNTER_PAGE);

    if (sel != 0)
    {
        printf2(TAG_ERR,"counter2 not imple\n");
        exit(1);
    }

    for (offset = 0; offset < PAGE_SIZE/4; offset += 1) // wear-level the flash
    {
        count = *(ptr+offset);
        if (count != 0)
        {
            count++;
            offset++;
            if (offset == PAGE_SIZE/4)
            {
                offset = 0;
                flash_erase_page(COUNTER_PAGE);
            }
            else
            {
                flash_write(flash_addr(COUNTER_PAGE)+offset-1,(uint8_t*)&zero,4);
            }
            flash_write(flash_addr(COUNTER_PAGE)+offset,(uint8_t*)&count,4);

            break;
        }
    }

    return count;
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

int ctap_user_presence_test()
{
#if SKIP_BUTTON_CHECK
    return 1;
#endif

    uint32_t t1 = millis();
    led_rgb(0xff3520);

#if USE_BUTTON_DELAY
    delay(3000);
    led_rgb(0x001040);
    delay(50);
    return 1;
#endif
while (IS_BUTTON_PRESSED())
{
    if (t1 + 5000 < millis())
    {
        printf1(TAG_GEN,"Button not pressed\n");
        return 0;
    }
}

t1 = millis();

do
{
    if (t1 + 5000 < millis())
    {
        return 0;
    }
    if (! IS_BUTTON_PRESSED())
        continue;
    delay(1);
}
while (! IS_BUTTON_PRESSED());

led_rgb(0x001040);

delay(50);

return 1;
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
