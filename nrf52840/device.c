/*
 * Device specific functionality here
 * */
#define DEBUG
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "nrf.h"
#include "nrf_error.h"
#include "nrf_drv_power.h"
#include "nrf_strerror.h"
#include "nrf_drv_rtc.h"
#include "nrf_drv_clock.h"
#include "nrf_drv_usbd.h"
#include "nrf_gpio.h"
#include "bsp.h"

#include "app_error.h"
#include "app_fifo.h"

#include "util.h"
#include "usb.h"
#include "device.h"
#include "cbor.h"
#include "log.h"



extern int _SEGGER_TERM;


void set_output_terminal(uint32_t term)
{
    _SEGGER_TERM = term;
}

void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    error_info_t * e = (error_info_t *)info;
    printf("Error: %d: %s at %d:%s\n",e->err_code, nrf_strerror_get(e->err_code), e->line_num, e->p_file_name);
    while(1)
        ;
}


void log_resetreason(void)
{
    /* Reset reason */
    uint32_t rr = nrf_power_resetreas_get();
    printf("Reset reasons:\n");
    if (0 == rr)
    {
        printf("- NONE\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_RESETPIN_MASK))
    {
        printf("- RESETPIN\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_DOG_MASK     ))
    {
        printf("- DOG\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_SREQ_MASK    ))
    {
        printf("- SREQ\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_LOCKUP_MASK  ))
    {
        printf("- LOCKUP\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_OFF_MASK     ))
    {
        printf("- OFF\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_LPCOMP_MASK  ))
    {
        printf("- LPCOMP\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_DIF_MASK     ))
    {
        printf("- DIF\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_NFC_MASK     ))
    {
        printf("- NFC\n");
    }
    if (0 != (rr & NRF_POWER_RESETREAS_VBUS_MASK    ))
    {
        printf("- VBUS\n");
    }
}


static const nrf_drv_rtc_t rtc = NRF_DRV_RTC_INSTANCE(0); /**< Declaring an instance of nrf_drv_rtc for RTC0. */
uint64_t millis()
{
    return (uint64_t)nrf_drv_rtc_counter_get(&rtc);
}



static void rtc_config(void)
{
    uint32_t err_code;

    //Initialize RTC instance
    nrf_drv_rtc_config_t config = NRF_DRV_RTC_DEFAULT_CONFIG;
    config.prescaler = 32;
    err_code = nrf_drv_rtc_init(&rtc, &config, NULL);
    APP_ERROR_CHECK(err_code);

    //Power on RTC instance
    nrf_drv_rtc_enable(&rtc);
}

static void init_power_clock(void)
{
    ret_code_t ret;
    /* Initializing power and clock */
    ret = nrf_drv_clock_init();
    APP_ERROR_CHECK(ret);
    ret = nrf_drv_power_init(NULL);
    APP_ERROR_CHECK(ret);
    nrf_drv_clock_hfclk_request(NULL);
    nrf_drv_clock_lfclk_request(NULL);
    while (!(nrf_drv_clock_hfclk_is_running() &&
            nrf_drv_clock_lfclk_is_running()))
    {
        /* Just waiting */
    }
}

void device_init()
{
    if ((nrf_power_resetreas_get() & NRF_POWER_RESETREAS_RESETPIN_MASK) == 0)
    {
        // Hard reset. this is for engineering A sample to work for USB ...
        nrf_power_resetreas_clear(nrf_power_resetreas_get());
        nrf_gpio_cfg_output(NRF_GPIO_PIN_MAP(0,31));
        nrf_gpio_pin_clear(NRF_GPIO_PIN_MAP(0,31));
        while (1)
            ;
    }
    nrf_power_resetreas_clear(nrf_power_resetreas_get());

    set_output_terminal(0);
    init_power_clock();
    rtc_config();
    usbhid_init();

    srand(millis());

    nrf_gpio_cfg_output(LED_1);
    nrf_gpio_cfg_output(LED_2);
    nrf_gpio_cfg_output(LED_3);
    nrf_gpio_cfg_output(LED_4);

    nrf_gpio_pin_toggle(LED_2);
    nrf_gpio_pin_toggle(LED_3);
}




static uint8_t fifo_buf[1024];
app_fifo_t USBHID_RECV_FIFO;

void usbhid_init()
{
#ifndef TEST_POWER
    app_fifo_init(&USBHID_RECV_FIFO, fifo_buf, sizeof(fifo_buf));
    usb_init();
#endif
}

// Receive 64 byte USB HID message, don't block, return size of packet, return 0 if nothing
#ifndef TEST_POWER
int usbhid_recv(uint8_t * msg)
{
    uint32_t size = 64;
    app_fifo_read(&USBHID_RECV_FIFO, msg, &size);
    return size;
}
#endif


// Send 64 byte USB HID message
void usbhid_send(uint8_t * msg)
{
    static nrf_drv_usbd_transfer_t transfer;
    transfer.p_data.tx = msg;
    transfer.size = 64;
    while (nrf_drv_usbd_ep_is_busy(NRF_DRV_USBD_EPIN1))
        ;
    nrf_drv_usbd_ep_transfer(
            NRF_DRV_USBD_EPIN1,
            &transfer);
}

void usbhid_close()
{
}


void main_loop_delay()
{
    // no delay on embedded system
}

void heartbeat()
{
    nrf_gpio_pin_toggle(LED_1);
    nrf_gpio_pin_toggle(LED_2);
    nrf_gpio_pin_toggle(LED_3);
    nrf_gpio_pin_toggle(LED_4);
}

#ifndef TEST_POWER
void ctaphid_write_block(uint8_t * data)
{
    printf1(TAG_DUMP,"<< "); dump_hex1(TAG_DUMP,data, 64);
    usbhid_send(data);
}
#endif


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
    static uint32_t counter2 = 25;
    /*return 713;*/
    if (sel == 0)
    {
        printf1(TAG_RED,"counter1: %d\n", counter1);
        return counter1++;
    }
    else
    {
        return counter2++;
    }
}

int ctap_generate_rng(uint8_t * dst, size_t num)
{
    int i;
    for (i = 0; i < num; i++)
    {
        *dst++ = (uint8_t)rand();
    }
    return 1;
}


