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

#define SOLO_FLAG_LOCKED                    0x2

void wait_for_usb_tether(void);


uint32_t __90_ms = 0;
uint32_t __last_button_press_time = 0;
uint32_t __last_button_bounce_time = 0;
uint32_t __device_status = 0;
uint32_t __last_update = 0;
extern PCD_HandleTypeDef hpcd;
static int _NFC_status = 0;
static bool isLowFreq = 0;
static bool _up_disabled = false;

// #define IS_BUTTON_PRESSED()         (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN))
static int is_physical_button_pressed(void)
{
    return (0  == (LL_GPIO_ReadInputPort(SOLO_BUTTON_PORT) & SOLO_BUTTON_PIN));
}

static int is_touch_button_pressed(void)
{
    int is_pressed = (tsc_read_button(0) || tsc_read_button(1));
#ifndef IS_BOOTLOADER
    if (is_pressed)
    {
        // delay for debounce, and longer than polling timer period.
        delay(95);
        return (tsc_read_button(0) || tsc_read_button(1));
    }
#endif
    return is_pressed;
}

int (*IS_BUTTON_PRESSED)() = is_physical_button_pressed;

static void edge_detect_touch_button(void)
{
    static uint8_t last_touch = 0;
    uint8_t current_touch = 0;
    if (is_touch_button_pressed == IS_BUTTON_PRESSED)
    {
        current_touch = (tsc_read_button(0) || tsc_read_button(1));

        // 1 sample per 25 ms
        if ((millis() - __last_button_bounce_time) > 25)
        {
            // Detect "touch / rising edge"
            if (!last_touch && current_touch)
            {
                __last_button_press_time = millis();
            }
            __last_button_bounce_time = millis();
            last_touch = current_touch;
        }
    }

}

void device_disable_up(bool disable)
{
    _up_disabled = disable;
}

// Timer6 overflow handler.  happens every ~90ms.
void TIM6_DAC_IRQHandler(void)
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

    edge_detect_touch_button();

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

uint32_t millis(void)
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

int device_is_button_pressed(void)
{
    return IS_BUTTON_PRESSED();
}

void delay(uint32_t ms)
{
    uint32_t time = millis();
    while ((millis() - time) < ms)
        ;
}

void device_reboot(void)
{
    NVIC_SystemReset();
}

void device_init_button(void)
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

int solo_is_locked(){
    uint64_t device_settings = ((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->device_settings;
    uint32_t tag = (uint32_t)(device_settings >> 32ull);
    return tag == ATTESTATION_CONFIGURED_TAG && (device_settings & SOLO_FLAG_LOCKED) != 0;
}

// Locks solo flash from debugging.  Locks on next reboot.
// This should be removed in next Solo release.
void solo_lock_if_not_already() {
    uint8_t buf[2048];

    memmove(buf, (uint8_t*)ATTESTATION_PAGE_ADDR, 2048);

    ((flash_attestation_page *)buf)->device_settings |= SOLO_FLAG_LOCKED;

    flash_erase_page(ATTESTATION_PAGE);

    flash_write(ATTESTATION_PAGE_ADDR, buf, 2048);
}

/** device_migrate
 * Depending on version of device, migrates:
 * * Moves attestation certificate to data segment. 
 * * Creates locked variable and stores in data segment.
 * 
 * Once in place, this allows all devices to accept same firmware,
 * rather than using "hacker" and "secure" builds.
*/
static void device_migrate(){
    extern const uint16_t attestation_solo_cert_der_size;
    extern const uint16_t attestation_hacker_cert_der_size;

    extern uint8_t attestation_solo_cert_der[];
    extern uint8_t attestation_hacker_cert_der[];

    uint64_t device_settings = ((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->device_settings;
    uint32_t configure_tag = (uint32_t)(device_settings >> 32);

    if (configure_tag != ATTESTATION_CONFIGURED_TAG)
    {
        printf1(TAG_RED,"Migrating certificate and lock information to data segment.\r\n");

        device_settings = ATTESTATION_CONFIGURED_TAG;
        device_settings <<= 32;

        // Read current device lock level.
        uint32_t optr = FLASH->OPTR;
        if ((optr & 0xff) != 0xAA){
            device_settings |= SOLO_FLAG_LOCKED;
        }

        uint8_t tmp_attestation_key[32];

        memmove(tmp_attestation_key,
            ((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_key,
            32);

        flash_erase_page(ATTESTATION_PAGE);
        flash_write(
            (uint32_t)((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_key,
            tmp_attestation_key,
            32
        );

        // Check if this is Solo Hacker attestation (not confidential)
        // then write solo or hacker attestation cert to flash page.
        uint8_t solo_hacker_attestation_key[32] = "\x1b\x26\x26\xec\xc8\xf6\x9b\x0f\x69\xe3\x4f"
                                                  "\xb2\x36\xd7\x64\x66\xba\x12\xac\x16\xc3\xab"
                                                  "\x57\x50\xba\x06\x4e\x8b\x90\xe0\x24\x48";

        if (memcmp(solo_hacker_attestation_key,
                   tmp_attestation_key,
                   32) == 0)
        {
            printf1(TAG_GREEN,"Updating solo hacker cert\r\n");
            flash_write_dword(
             (uint32_t)&((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_cert_size,
             (uint64_t)attestation_hacker_cert_der_size
             );
            flash_write(
                (uint32_t)((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_cert,
                attestation_hacker_cert_der,
                attestation_hacker_cert_der_size
            );
        }
        else
        {
            printf1(TAG_GREEN,"Updating solo secure cert\r\n");
            flash_write_dword(
             (uint32_t)&((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_cert_size,
             (uint64_t)attestation_solo_cert_der_size
             );
            flash_write(
                (uint32_t)((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->attestation_cert,
                attestation_solo_cert_der,
                attestation_solo_cert_der_size
            );
        }

        // Save / done.
        flash_write_dword(
            (uint32_t) & ((flash_attestation_page *)ATTESTATION_PAGE_ADDR)->device_settings,
            (uint64_t)device_settings);
    }
}

void device_init()
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

    device_migrate();

#if BOOT_TO_DFU
    flash_option_bytes_init(1);
#else
    flash_option_bytes_init(0);
#endif

    usbhid_init();
    ctaphid_init();
    ctap_init();

}

int device_is_nfc(void)
{
    return _NFC_status;
}

void wait_for_usb_tether(void)
{
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
    delay(10);
    while (USBD_OK != CDC_Transmit_FS((uint8_t*)"tethered\r\n", 10) )
        ;
}

void usbhid_init(void)
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


void usbhid_close(void)
{

}

void main_loop_delay(void)
{

}

static int wink_time = 0;
static uint32_t winkt1 = 0;
#ifdef LED_WINK_VALUE
static uint32_t winkt2 = 0;
#endif

void device_wink(void)
{
    wink_time = 10;
    winkt1 = 0;
}

void heartbeat(void)
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


static int authenticator_is_backup_initialized(void)
{
    uint8_t header[16];
    uint32_t * ptr = (uint32_t *)flash_addr(STATE2_PAGE);
    memmove(header,ptr,16);
    AuthenticatorState * state = (AuthenticatorState*)header;
    return state->is_initialized == INITIALIZED_MARKER;
}

int authenticator_read_state(AuthenticatorState * a)
{
    uint32_t * ptr = (uint32_t *) flash_addr(STATE1_PAGE);
    memmove(a, ptr, sizeof(AuthenticatorState));

    if (a->is_initialized != INITIALIZED_MARKER){

        if (authenticator_is_backup_initialized()){
            printf1(TAG_ERR,"Warning: memory corruption detected.  restoring from backup..\n");
            ptr = (uint32_t *) flash_addr(STATE2_PAGE);
            memmove(a, ptr, sizeof(AuthenticatorState));
            authenticator_write_state(a);
            return 1;
        }

        return 0;
    }

    return 1;
}


void authenticator_write_state(AuthenticatorState * a)
{
    flash_erase_page(STATE1_PAGE);
    flash_write(flash_addr(STATE1_PAGE), (uint8_t*)a, sizeof(AuthenticatorState));

    flash_erase_page(STATE2_PAGE);
    flash_write(flash_addr(STATE2_PAGE), (uint8_t*)a, sizeof(AuthenticatorState));
}

#if !defined(IS_BOOTLOADER)
uint32_t ctap_atomic_count(uint32_t amount)
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

    if (amount == 0)
    {
        // Use a random count [1-16].
        uint8_t rng[1];
        ctap_generate_rng(rng, 1);
        amount = (rng[0] & 0x0f) + 1;
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

    if (amount > 256){
        lastc = amount;
    } else {
        lastc += amount;
    }

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
#endif


void device_manage(void)
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

static int handle_packets(void)
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

    if (device_is_nfc() == NFC_IS_ACTIVE)
    {
        return 1;
    }

    if (_up_disabled)
    {
        return 2;
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


void ctap_reset_rk(void)
{
    int i;
    printf1(TAG_GREEN, "resetting RK \r\n");
    for(i = 0; i < RK_NUM_PAGES; i++)
    {
        flash_erase_page(RK_START_PAGE + i);
    }
}

uint32_t ctap_rk_size(void)
{
    return RK_NUM_PAGES * (PAGE_SIZE / sizeof(CTAP_residentKey));
}

void ctap_store_rk(int index,CTAP_residentKey * rk)
{
    ctap_overwrite_rk(index, rk);
}

void ctap_delete_rk(int index)
{
    CTAP_residentKey rk;
    memset(&rk, 0xff, sizeof(CTAP_residentKey));
    ctap_overwrite_rk(index, &rk);
}

void ctap_load_rk(int index,CTAP_residentKey * rk)
{
    int byte_offset_into_page = (sizeof(CTAP_residentKey) * (index % (PAGE_SIZE/sizeof(CTAP_residentKey))));
    int page_offset = (index)/(PAGE_SIZE/sizeof(CTAP_residentKey));

    uint32_t addr = flash_addr(page_offset + RK_START_PAGE) + byte_offset_into_page;

    printf1(TAG_GREEN, "reading RK %d @ %04x\r\n", index, addr);
    if (page_offset < RK_NUM_PAGES)
    {
        uint32_t * ptr = (uint32_t *)addr;
        memmove((uint8_t*)rk,ptr,sizeof(CTAP_residentKey));
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
}

void ctap_overwrite_rk(int index,CTAP_residentKey * rk)
{
    uint8_t tmppage[PAGE_SIZE];

    int byte_offset_into_page = (sizeof(CTAP_residentKey) * (index % (PAGE_SIZE/sizeof(CTAP_residentKey))));
    int page_offset = (index)/(PAGE_SIZE/sizeof(CTAP_residentKey));

    printf1(TAG_GREEN, "overwriting RK %d @ page %d @ addr 0x%08x-0x%08x\r\n", 
        index, RK_START_PAGE + page_offset, 
        flash_addr(RK_START_PAGE + page_offset) + byte_offset_into_page, 
        flash_addr(RK_START_PAGE + page_offset) + byte_offset_into_page + sizeof(CTAP_residentKey) 
        );
    if (page_offset < RK_NUM_PAGES)
    {
        memmove(tmppage, (uint8_t*)flash_addr(RK_START_PAGE + page_offset), PAGE_SIZE);

        memmove(tmppage + byte_offset_into_page, rk, sizeof(CTAP_residentKey));
        flash_erase_page(RK_START_PAGE + page_offset);
        flash_write(flash_addr(RK_START_PAGE + page_offset), tmppage, PAGE_SIZE);
    }
    else
    {
        printf2(TAG_ERR,"Out of bounds reading index %d for rk\n", index);
    }
    printf1(TAG_GREEN, "4\r\n");
}

void boot_st_bootloader(void)
{
    __disable_irq();

    __set_MSP(*((uint32_t *)0x1fff0000));

    ((void (*)(void)) (*((uint32_t *)0x1fff0004)))();

    while(1)
    ;
}

void boot_solo_bootloader(void)
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

void device_read_aaguid(uint8_t * dst){
    uint8_t * aaguid = (uint8_t *)"\x88\x76\x63\x1b\xd4\xa0\x42\x7f\x57\x73\x0e\xc7\x1c\x9e\x02\x79";
    memmove(dst, aaguid, 16);
    if (device_is_nfc()){
        dst[0] = 0x89;
    }
    else if (tsc_sensor_exists()){
        dst[0] = 0x98;
    }
    dump_hex1(TAG_GREEN,dst, 16);
}


void _Error_Handler(char *file, int line)
{
    printf2(TAG_ERR,"Error: %s: %d\r\n", file, line);
    while(1)
    {
    }
}
