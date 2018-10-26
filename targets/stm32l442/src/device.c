
#include "device.h"
#include "usbd_def.h"
#include "stm32l4xx.h"
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

uint32_t __65_seconds = 0;
extern PCD_HandleTypeDef hpcd;

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
    // int but = IS_BUTTON_PRESSED();
    int but = 0;

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
    // int c = PCD_GET_EP_TX_CNT(USB,1);
    // int c = PCD_GET_EP_TX_STATUS(USB,1);
    // printf("tx counter: %x\r\n",PCD_GET_EP_TX_CNT(USB,1));

    //	if (but) RGB(val * 2);
    //	else
    led_rgb((val << 16) | (val*2 << 8));
}

void authenticator_read_state(AuthenticatorState * a)
{

}

void authenticator_read_backup_state(AuthenticatorState * a)
{

}

// Return 1 yes backup is init'd, else 0
//void authenticator_initialize()
int authenticator_is_backup_initialized()
{
    return 0;
}

void authenticator_write_state(AuthenticatorState * a, int backup)
{

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
    return 1;
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    rng_get_bytes(dst, num);
    return 1;
}

uint32_t ctap_atomic_count(int sel)
{
    static uint32_t c = 4;
    return c++;
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
