// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include "device.h"
#include "usbd_def.h"
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_tim.h"
#include "stm32l4xx_ll_usart.h"
#include "stm32l4xx_ll_pwr.h"
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
#include "memory_layout.h"
#include "stm32l4xx_ll_iwdg.h"
#include "usbd_cdc_if.h"
#include "nfc.h"
#include "init.h"
#include "sense.h"

#define LOW_FREQUENCY        1
#define HIGH_FREQUENCY       0

void wait_for_usb_tether();


uint32_t __90_ms = 0;
uint32_t __last_button_press_time = 0;
uint32_t __last_button_bounce_time = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
extern PCD_HandleTypeDef hpcd;
static int _NFC_status = 0;
static bool isLowFreq = 0;
static bool _RequestComeFromNFC = false;

// #define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))
static int is_physical_button_pressed()
{
    return (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN));
}

static int is_touch_button_pressed()
{
    return tsc_read_button(0) || tsc_read_button(1);
}

int (*IS_BUTTON_PRESSED)() = is_physical_button_pressed;

void request_from_nfc(bool request_active) {
    _RequestComeFromNFC = request_active;
}

// Timer6 overflow handler.  happens every ~90ms.
void TIM6_DAC_IRQHandler()
{
    // timer is only 16 bits, so roll it over here
    TIM6->SR = 0;
    __90_ms += 1;
    if ((millis() - __last_update) > 90)
    {
        if (__device_status != CTAPHID_STATUS_IDLE)
        {
            ctaphid_update_status(__device_status);
        }
    }


    if (is_touch_button_pressed == IS_BUTTON_PRESSED)
    {
        if (IS_BUTTON_PRESSED())
        {
            // Only allow 1 press per 25 ms.
            if ((millis() - __last_button_bounce_time) > 25)
            {
                __last_button_press_time = millis();
            }
            __last_button_bounce_time = millis();
        }
    }

#ifndef IS_BOOTLOADER
	// NFC sending WTX if needs
	if (device_is_nfc() == NFC_IS_ACTIVE)
	{
		WTX_timer_exec();
	}
#endif
}

// Interrupt on rising edge of button (button released)
void EXTI0_IRQHandler(void)
{
    EXTI->PR1 = EXTI->PR1;
    if (is_physical_button_pressed == IS_BUTTON_PRESSED)
    {
        // Only allow 1 press per 25 ms.
        if ((millis() - __last_button_bounce_time) > 25)
        {
            __last_button_press_time = millis();
        }
        __last_button_bounce_time = millis();
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

void device_set_status(uint32_t status)
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
    NVIC_SystemReset();
}

void device_init_button()
{
    if (tsc_sensor_exists())
    {
        tsc_init();
        IS_BUTTON_PRESSED = is_touch_button_pressed;
    }
    else
    {
        IS_BUTTON_PRESSED = is_physical_button_pressed;
    }
}

void device_init(int argc, char *argv[])
{

    hw_init(LOW_FREQUENCY);

    if (! tsc_sensor_exists())
    {
        _NFC_status = nfc_init();
    }

    if (_NFC_status == NFC_IS_ACTIVE)
    {
        printf1(TAG_NFC, "Have NFC\r\n");
        isLowFreq = 1;
        IS_BUTTON_PRESSED = is_physical_button_pressed;
    }
    else
    {
        printf1(TAG_NFC, "Have NO NFC\r\n");
        hw_init(HIGH_FREQUENCY);
        isLowFreq = 0;
        device_init_button();
    }

    usbhid_init();
    ctaphid_init();
    ctap_init();

#if BOOT_TO_DFU
    flash_option_bytes_init(1);
#else
    flash_option_bytes_init(0);
#endif


}

int device_is_nfc()
{
    return _NFC_status;
}

void wait_for_usb_tether()
{
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
    delay(10);
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
}

void usbhid_init()
{
    if (!isLowFreq)
    {
        init_usb();

#if DEBUG_LEVEL>1
        wait_for_usb_tether();
#endif
    }
    else
    {



    }
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

static int wink_time = 0;
static uint32_t winkt1 = 0;
#ifdef LED_WINK_VALUE
static uint32_t winkt2 = 0;
#endif
void device_wink()
{
    wink_time = 10;
    winkt1 = 0;
}

void heartbeat()
{
    static int state = 0;
    static uint32_t val = (LED_MAX_SCALER - LED_MIN_SCALER)/2;
    uint8_t r = (LED_INIT_VALUE >> 16) & 0xff;
    uint8_t g = (LED_INIT_VALUE >> 8) & 0xff;
    uint8_t b = (LED_INIT_VALUE >> 0) & 0xff;
    int but = IS_BUTTON_PRESSED();

    if (state)
    {
        val--;
    }
    else
    {
        val++;
    }

    if (val >= LED_MAX_SCALER || val <= LED_MIN_SCALER)
    {
        state = !state;

		if (val > LED_MAX_SCALER)
			val = LED_MAX_SCALER;
		if (val < LED_MIN_SCALER)
			val = LED_MIN_SCALER;
    }

#ifdef LED_WINK_VALUE
    if (wink_time)
    {
        if (millis() - winkt1 > 120)
        {
            winkt1 = millis();
            if (winkt2++ & 1)
            {
                led_rgb(LED_WINK_VALUE * (LED_MAX_SCALER - LED_MIN_SCALER)/2);
            }
            else
            {
                led_rgb(0);
            }
            wink_time--;
        }
    }
    else
#endif
    {
        if (but)
            led_rgb(((val * r)<<8) | ((val*b) << 16) | (val*g));
        else
            led_rgb(((val * g)<<8) | ((val*r) << 16) | (val*b));
    }

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
#ifndef IS_BOOTLOADER
	if(device_is_nfc())
		nfc_loop();
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

static int wait_for_button_activate(uint32_t wait)
{
    int ret;
    uint32_t start = millis();
    do
    {
        if ((start + wait) < millis())
        {
            return 0;
        }
        delay(1);
        ret = handle_packets();
        if (ret)
            return ret;
    } while (!IS_BUTTON_PRESSED());
    return 0;
}
static int wait_for_button_release(uint32_t wait)
{
    int ret;
    uint32_t start = millis();
    do
    {
        if ((start + wait) < millis())
        {
            return 0;
        }
        delay(1);
        ret = handle_packets();
        if (ret)
            return ret;
    } while (IS_BUTTON_PRESSED());
    return 0;
}

int ctap_user_presence_test(uint32_t up_delay)
{
    int ret;
    if (device_is_nfc() == NFC_IS_ACTIVE || _RequestComeFromNFC)
    {
        return 1;
    }

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
    if (ret)
        return ret;
    goto done;
#endif

    // If button was pressed within last [2] seconds, succeed.
    if (__last_button_press_time && (millis() - __last_button_press_time < 2000))
    {
        goto done;
    }

    // Set LED status and wait.
    led_rgb(0xff3520);

    // Block and wait for some time.
    ret = wait_for_button_activate(up_delay);
    if (ret) return ret;
    ret = wait_for_button_release(up_delay);
    if (ret) return ret;

    // If button was pressed within last [2] seconds, succeed.
    if (__last_button_press_time && (millis() - __last_button_press_time < 2000))
    {
        goto done;
    }


    return 0;


done:
    ret = wait_for_button_release(up_delay);
    __last_button_press_time = 0;
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
        flash_write(flash_addr(page), tmppage, PAGE_SIZE);
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
}

void boot_st_bootloader()
{
    __disable_irq();

    __set_MSP(*((uint32_t *)0x1fff0000));

    ((void (*)(void)) (*((uint32_t *)0x1fff0004)))();

    while(1)
    ;
}

void boot_solo_bootloader()
{
    LL_IWDG_Enable(IWDG);

    LL_IWDG_EnableWriteAccess(IWDG);

    LL_IWDG_SetPrescaler(IWDG, LL_IWDG_PRESCALER_4);

    LL_IWDG_SetWindow(IWDG, 4095);

    LL_IWDG_SetReloadCounter(IWDG, 2000); // ~0.25s

    while (LL_IWDG_IsReady(IWDG) != 1)
    {
    }

    LL_IWDG_ReloadCounter(IWDG);

}



void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}
