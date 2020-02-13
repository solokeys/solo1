// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_rcc.h"
#include "stm32l4xx_ll_crs.h"
#include "stm32l4xx_ll_system.h"
#include "stm32l4xx_ll_pwr.h"
#include "stm32l4xx_ll_utils.h"
#include "stm32l4xx_ll_cortex.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_usart.h"
#include "stm32l4xx_ll_bus.h"
#include "stm32l4xx_ll_tim.h"
#include "stm32l4xx_ll_rng.h"
#include "stm32l4xx_ll_spi.h"
#include "stm32l4xx_ll_usb.h"
#include "stm32l4xx_ll_exti.h"
#include "stm32l4xx_hal_pcd.h"
#include "stm32l4xx_hal.h"

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
#include "usbd_cdc.h"
#include "usbd_ccid.h"
#include "usbd_composite.h"
#include "usbd_cdc_if.h"
#include "device.h"
#include "init.h"
#include "sense.h"
#include APP_CONFIG

// KHz
#define MAX_CLOCK_RATE      24000

#define SET_CLOCK_RATE2()        SystemClock_Config()

#if MAX_CLOCK_RATE == 48000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF32()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF48()
#elif MAX_CLOCK_RATE == 32000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF24()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF32()
#elif MAX_CLOCK_RATE == 28000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF24()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF28()
#elif MAX_CLOCK_RATE == 24000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF16()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF24()
#elif MAX_CLOCK_RATE == 20000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF16()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF20()
#elif MAX_CLOCK_RATE == 16000
    #define SET_CLOCK_RATE0()        SystemClock_Config_LF8()
    #define SET_CLOCK_RATE1()        SystemClock_Config_LF16()
#else
#error "Invalid clock rate selected"
#endif

USBD_HandleTypeDef Solo_USBD_Device;

static void LL_Init(void);

#define Error_Handler() _Error_Handler(__FILE__,__LINE__)
void _Error_Handler(char *file, int line);

void SystemClock_Config(void);
void SystemClock_Config_LF16(void);
void SystemClock_Config_LF20(void);
void SystemClock_Config_LF24(void);
void SystemClock_Config_LF28(void);
void SystemClock_Config_LF48(void);

void hw_init(int lowfreq)
{
#ifdef IS_BOOTLOADER
    SCB->VTOR = FLASH_BASE;
#else
#endif
    LL_Init();
    init_gpio();

    if (lowfreq)
    {
        LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE2); // Under voltage
        device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
        LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE2);
    }
    else
    {
        SystemClock_Config();
    }

    if (!lowfreq)
    {
        init_pwm();
    }

    init_millisecond_timer(lowfreq);

#if DEBUG_LEVEL > 0
    init_debug_uart();
#endif

    init_rng();

    init_spi();

}

static void LL_Init(void)
{
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_SYSCFG);
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_PWR);

    NVIC_SetPriorityGrouping(4);

    /* System interrupt init*/
    /* MemoryManagement_IRQn interrupt configuration */
    NVIC_SetPriority(MemoryManagement_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* BusFault_IRQn interrupt configuration */
    NVIC_SetPriority(BusFault_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* UsageFault_IRQn interrupt configuration */
    NVIC_SetPriority(UsageFault_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* SVCall_IRQn interrupt configuration */
    NVIC_SetPriority(SVCall_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* DebugMonitor_IRQn interrupt configuration */
    NVIC_SetPriority(DebugMonitor_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* PendSV_IRQn interrupt configuration */
    NVIC_SetPriority(PendSV_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

}

void device_set_clock_rate(DEVICE_CLOCK_RATE param)
{
    switch(param)
    {
        case DEVICE_LOW_POWER_IDLE:
            SET_CLOCK_RATE0();
        break;
#if !defined(IS_BOOTLOADER)
        case DEVICE_LOW_POWER_FAST:
            SET_CLOCK_RATE1();
        break;
        case DEVICE_FAST:
            SET_CLOCK_RATE2();
        break;
#endif
    }
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

      LL_FLASH_SetLatency(LL_FLASH_LATENCY_2);

       if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_2)
      {
      Error_Handler();
      }
      LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

      LL_RCC_HSI48_Enable();

       /* Wait till HSI48 is ready */
      while(LL_RCC_HSI48_IsReady() != 1)
      {

      }

      LL_RCC_LSI_Enable();

       /* Wait till LSI is ready */
      while(LL_RCC_LSI_IsReady() != 1)
      {

      }
      LL_RCC_MSI_Enable();
       /* Wait till MSI is ready */
      while(LL_RCC_MSI_IsReady() != 1)
      {

      }
      LL_RCC_MSI_EnableRangeSelection();

      LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_11);

      LL_RCC_MSI_SetCalibTrimming(0);

      LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

       /* Wait till System clock is ready */
      while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
      {

      }
      LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

      LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

      LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_16);

      LL_Init1msTick(48000000);

      LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

      LL_SetSystemCoreClock(48000000);

      LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

      LL_RCC_SetUSBClockSource(LL_RCC_USB_CLKSOURCE_HSI48);

      LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_CRS);

      LL_APB1_GRP1_ForceReset(LL_APB1_GRP1_PERIPH_CRS);

      LL_APB1_GRP1_ReleaseReset(LL_APB1_GRP1_PERIPH_CRS);

      LL_CRS_SetSyncDivider(LL_CRS_SYNC_DIV_1);

      LL_CRS_SetSyncPolarity(LL_CRS_SYNC_POLARITY_RISING);

      LL_CRS_SetSyncSignalSource(LL_CRS_SYNC_SOURCE_USB);

      LL_CRS_SetReloadCounter(__LL_CRS_CALC_CALCULATE_RELOADVALUE(48000000,1000));

      LL_CRS_SetFreqErrorLimit(34);

      LL_CRS_SetHSI48SmoothTrimming(32);

      /* SysTick_IRQn interrupt configuration */
      NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
}

void SystemClock_Config_LF4(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

    LL_RCC_LSI_Enable();

     /* Wait till LSI is ready */
    while(LL_RCC_LSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_Enable();

     /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_6);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

     /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_1);

    LL_Init1msTick(4000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(4000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_0);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_0)
    {
        Error_Handler();
    }
}

// 8MHz
void SystemClock_Config_LF8(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

    LL_RCC_LSI_Enable();

     /* Wait till LSI is ready */
    while(LL_RCC_LSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_Enable();

     /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_7);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

     /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_1);

    LL_Init1msTick(8000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(8000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_0);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_0)
    {
        Error_Handler();
    }
}

// 16MHz
void SystemClock_Config_LF16(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE2);

    LL_RCC_LSI_Enable();

     /* Wait till LSI is ready */
    while(LL_RCC_LSI_IsReady() != 1)
    {

    }

    LL_RCC_MSI_Enable();

     /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_8);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

     /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_8);

    LL_Init1msTick(16000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(16000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_0);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_0)
    {
        Error_Handler();
    }

}



// 24 MHz
void SystemClock_Config_LF24(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_1);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_1)
    {
        Error_Handler();
    }
    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE2);

    LL_RCC_LSI_Enable();

     /* Wait till LSI is ready */
    while(LL_RCC_LSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_Enable();

     /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_9);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

     /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_8);

    LL_Init1msTick(24000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(24000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

}

// 32 MHz
void SystemClock_Config_LF32(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_1);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_1)
    {
    Error_Handler();
    }
    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

    LL_RCC_LSI_Enable();

     /* Wait till LSI is ready */
    while(LL_RCC_LSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_Enable();

     /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_10);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

     /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_16);

    LL_Init1msTick(32000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(32000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

    LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));

}

// 28 MHz
void SystemClock_Config_LF28(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);
  LL_FLASH_SetLatency(LL_FLASH_LATENCY_1);

  if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_1)
  {
  Error_Handler();
  }
  LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

  LL_RCC_HSI_Enable();

   /* Wait till HSI is ready */
  while(LL_RCC_HSI_IsReady() != 1)
  {

  }
  LL_RCC_HSI_SetCalibTrimming(16);

  LL_RCC_LSI_Enable();

   /* Wait till LSI is ready */
  while(LL_RCC_LSI_IsReady() != 1)
  {

  }
  LL_RCC_MSI_Enable();

   /* Wait till MSI is ready */
  while(LL_RCC_MSI_IsReady() != 1)
  {

  }
  LL_RCC_MSI_EnableRangeSelection();

  LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_6);

  LL_RCC_MSI_SetCalibTrimming(0);

  LL_RCC_PLL_ConfigDomain_SYS(LL_RCC_PLLSOURCE_HSI, LL_RCC_PLLM_DIV_2, 28, LL_RCC_PLLR_DIV_8);

  LL_RCC_PLL_EnableDomain_SYS();

  LL_RCC_PLL_Enable();

   /* Wait till PLL is ready */
  while(LL_RCC_PLL_IsReady() != 1)
  {

  }
  LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_PLL);

   /* Wait till System clock is ready */
  while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_PLL)
  {

  }
  LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

  LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

  LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_8);

  LL_Init1msTick(28000000);

  LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

  LL_SetSystemCoreClock(28000000);

  LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

  LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

  /* SysTick_IRQn interrupt configuration */
  NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
}

// 48 MHz
void SystemClock_Config_LF48(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);


    LL_FLASH_SetLatency(LL_FLASH_LATENCY_2);

      if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_2)
     {
     Error_Handler();
     }
     LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

     LL_RCC_LSI_Enable();

      /* Wait till LSI is ready */
     while(LL_RCC_LSI_IsReady() != 1)
     {

     }
     LL_RCC_MSI_Enable();

      /* Wait till MSI is ready */
     while(LL_RCC_MSI_IsReady() != 1)
     {

     }
     LL_RCC_MSI_EnableRangeSelection();

     LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_11);

     LL_RCC_MSI_SetCalibTrimming(0);

     LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

      /* Wait till System clock is ready */
     while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
     {

     }
     LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

     LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);

     LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_16);

     LL_Init1msTick(48000000);

     LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

     LL_SetSystemCoreClock(48000000);

     LL_RCC_SetUSARTClockSource(LL_RCC_USART1_CLKSOURCE_PCLK2);

     LL_RCC_SetRNGClockSource(LL_RCC_RNG_CLKSOURCE_MSI);

     /* SysTick_IRQn interrupt configuration */
     NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));


}

// 20 MHz
void SystemClock_Config_LF20(void)
{
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);
}

void init_usb(void)
{
    // enable USB power
    SET_BIT(PWR->CR2, PWR_CR2_USV);

    // Enable USB Clock
    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_USBFSEN);
#ifndef IS_BOOTLOADER
    USBD_Composite_Set_Classes(&USBD_HID, &USBD_CCID, &USBD_CDC);
    in_endpoint_to_class[HID_EPIN_ADDR & 0x7F] = 0;
    out_endpoint_to_class[HID_EPOUT_ADDR & 0x7F] = 0;

    in_endpoint_to_class[CCID_IN_EP & 0x7F] = 1;
    out_endpoint_to_class[CCID_OUT_EP & 0x7F] = 1;

    in_endpoint_to_class[CDC_IN_EP & 0x7F] = 2;
    out_endpoint_to_class[CDC_OUT_EP & 0x7F] = 2;

    USBD_Init(&Solo_USBD_Device, &Solo_Desc, 0);
    USBD_RegisterClass(&Solo_USBD_Device, &USBD_Composite);
#if DEBUG_LEVEL > 0
    USBD_CDC_RegisterInterface(&Solo_USBD_Device, &USBD_Interface_fops_FS);
#endif
#else
    USBD_Init(&Solo_USBD_Device, &Solo_Desc, 0);
    USBD_RegisterClass(&Solo_USBD_Device, &USBD_HID);
#endif
    USBD_Start(&Solo_USBD_Device);
}

void init_pwm(void)
{

    LL_TIM_InitTypeDef TIM_InitStruct;
    LL_TIM_OC_InitTypeDef TIM_OC_InitStruct;

    LL_GPIO_InitTypeDef GPIO_InitStruct;

    /* Peripheral clock enable */
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_TIM2);

    TIM2->SR = 0 ;

    TIM_InitStruct.Prescaler = 0;
    TIM_InitStruct.CounterMode = LL_TIM_COUNTERMODE_UP;
    TIM_InitStruct.Autoreload = 1000;
    TIM_InitStruct.ClockDivision = LL_TIM_CLOCKDIVISION_DIV1;
    LL_TIM_Init(TIM2, &TIM_InitStruct);

    LL_TIM_EnableARRPreload(TIM2);

    LL_TIM_SetClockSource(TIM2, LL_TIM_CLOCKSOURCE_INTERNAL);

    TIM_OC_InitStruct.OCMode = LL_TIM_OCMODE_PWM1;
    TIM_OC_InitStruct.OCState = LL_TIM_OCSTATE_ENABLE;
    TIM_OC_InitStruct.OCNState = LL_TIM_OCSTATE_ENABLE;
    TIM_OC_InitStruct.CompareValue = 1000;
    TIM_OC_InitStruct.OCPolarity = LL_TIM_OCPOLARITY_HIGH;
    LL_TIM_OC_Init(TIM2, LL_TIM_CHANNEL_CH2, &TIM_OC_InitStruct);

    LL_TIM_OC_DisableFast(TIM2, LL_TIM_CHANNEL_CH2);

    TIM_OC_InitStruct.OCState = LL_TIM_OCSTATE_ENABLE;
    TIM_OC_InitStruct.OCNState = LL_TIM_OCSTATE_ENABLE;
    LL_TIM_OC_Init(TIM2, LL_TIM_CHANNEL_CH3, &TIM_OC_InitStruct);

    LL_TIM_OC_DisableFast(TIM2, LL_TIM_CHANNEL_CH3);

    TIM_OC_InitStruct.OCState = LL_TIM_OCSTATE_ENABLE;
    TIM_OC_InitStruct.OCNState = LL_TIM_OCSTATE_ENABLE;
    LL_TIM_OC_Init(TIM2, LL_TIM_CHANNEL_CH4, &TIM_OC_InitStruct);

    LL_TIM_OC_DisableFast(TIM2, LL_TIM_CHANNEL_CH4);

    LL_TIM_SetOCRefClearInputSource(TIM2, LL_TIM_OCREF_CLR_INT_NC);

    LL_TIM_DisableExternalClock(TIM2);

    LL_TIM_ConfigETR(TIM2, LL_TIM_ETR_POLARITY_NONINVERTED, LL_TIM_ETR_PRESCALER_DIV1, LL_TIM_ETR_FILTER_FDIV1);

    LL_TIM_SetTriggerOutput(TIM2, LL_TIM_TRGO_RESET);

    LL_TIM_DisableMasterSlaveMode(TIM2);

    /**TIM2 GPIO Configuration
    PA1   ------> TIM2_CH2
    PA2   ------> TIM2_CH3
    PA3   ------> TIM2_CH4
    */
    GPIO_InitStruct.Pin = LL_GPIO_PIN_1|LL_GPIO_PIN_2|LL_GPIO_PIN_3;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct.Alternate = LL_GPIO_AF_1;
    LL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    LL_TIM_EnableCounter(TIM2);

}

void init_debug_uart(void)
{

  LL_USART_InitTypeDef USART_InitStruct;

  LL_GPIO_InitTypeDef GPIO_InitStruct;

  /* Peripheral clock enable */
  LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_USART1);


  LL_USART_DeInit(USART1);
  /**USART1 GPIO Configuration
  PB6   ------> USART1_TX
  PB7   ------> USART1_RX
  */
  GPIO_InitStruct.Pin = LL_GPIO_PIN_6|LL_GPIO_PIN_7;
  GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
  GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
  GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
  GPIO_InitStruct.Alternate = LL_GPIO_AF_7;
  LL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  USART_InitStruct.BaudRate = 115200;
  USART_InitStruct.DataWidth = LL_USART_DATAWIDTH_8B;
  USART_InitStruct.StopBits = LL_USART_STOPBITS_1;
  USART_InitStruct.Parity = LL_USART_PARITY_NONE;
  USART_InitStruct.TransferDirection = LL_USART_DIRECTION_TX_RX;
  USART_InitStruct.HardwareFlowControl = LL_USART_HWCONTROL_NONE;
  USART_InitStruct.OverSampling = LL_USART_OVERSAMPLING_16;
  LL_USART_Init(USART1, &USART_InitStruct);

  LL_USART_ConfigAsyncMode(USART1);

  LL_USART_Enable(USART1);

}

void init_gpio(void)
{

  /* GPIO Ports Clock Enable */
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_GPIOA);
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_GPIOB);



  LL_GPIO_SetPinMode(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_MODE_INPUT);
  LL_GPIO_SetPinPull(SOLO_BUTTON_PORT,SOLO_BUTTON_PIN,LL_GPIO_PULL_UP);

#ifndef IS_BOOTLOADER
  LL_SYSCFG_SetEXTISource(LL_SYSCFG_EXTI_PORTA, LL_SYSCFG_EXTI_LINE0);
  LL_EXTI_InitTypeDef EXTI_InitStruct;
  EXTI_InitStruct.Line_0_31 = LL_EXTI_LINE_0;   // GPIOA_0
  EXTI_InitStruct.Line_32_63 = LL_EXTI_LINE_NONE;
  EXTI_InitStruct.LineCommand = ENABLE;
  EXTI_InitStruct.Mode = LL_EXTI_MODE_IT;
  EXTI_InitStruct.Trigger = LL_EXTI_TRIGGER_RISING;
  LL_EXTI_Init(&EXTI_InitStruct);

  NVIC_EnableIRQ(EXTI0_IRQn);
#endif

}

void init_millisecond_timer(int lf)
{

    LL_TIM_InitTypeDef TIM_InitStruct;

    /* Peripheral clock enable */
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_TIM6);

    // 48 MHz sys clock --> 6 MHz timer clock
    // 48 MHz / 48000 == 1000 Hz
    if (!lf)
        TIM_InitStruct.Prescaler = 48000;
    else
        TIM_InitStruct.Prescaler = MAX_CLOCK_RATE;

    TIM_InitStruct.CounterMode = LL_TIM_COUNTERMODE_UP;
    TIM_InitStruct.Autoreload = 90;
    LL_TIM_Init(TIM6, &TIM_InitStruct);

    LL_TIM_DisableARRPreload(TIM6);

    LL_TIM_SetTriggerOutput(TIM6, LL_TIM_TRGO_RESET);

    LL_TIM_DisableMasterSlaveMode(TIM6);

    // enable interrupt
    TIM6->DIER |= 1;

    // Start immediately
    LL_TIM_EnableCounter(TIM6);

    TIM6->SR = 0;
    __enable_irq();
    NVIC_EnableIRQ(TIM6_IRQn);
}


void init_rng(void)
{

  /* Peripheral clock enable */
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_RNG);

  LL_RNG_Enable(RNG);

}

/* SPI1 init function */
void init_spi(void)
{

    LL_SPI_InitTypeDef SPI_InitStruct;

    LL_GPIO_InitTypeDef GPIO_InitStruct;

    /* Peripheral clock enable */
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_SPI1);

    /**SPI1 GPIO Configuration
    PA5   ------> SPI1_SCK
    PA6   ------> SPI1_MISO
    PA7   ------> SPI1_MOSI
    */
    GPIO_InitStruct.Pin = LL_GPIO_PIN_5|LL_GPIO_PIN_6|LL_GPIO_PIN_7;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct.Alternate = LL_GPIO_AF_5;
    LL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    /* SPI1 parameter configuration*/
    SPI_InitStruct.TransferDirection = LL_SPI_FULL_DUPLEX;
    SPI_InitStruct.Mode = LL_SPI_MODE_MASTER;
    SPI_InitStruct.DataWidth = LL_SPI_DATAWIDTH_8BIT;
    SPI_InitStruct.ClockPolarity = LL_SPI_POLARITY_LOW;
    SPI_InitStruct.ClockPhase = LL_SPI_PHASE_2EDGE;
    SPI_InitStruct.NSS = LL_SPI_NSS_SOFT;
    SPI_InitStruct.BaudRate = LL_SPI_BAUDRATEPRESCALER_DIV8;
    SPI_InitStruct.BitOrder = LL_SPI_MSB_FIRST;
    SPI_InitStruct.CRCCalculation = LL_SPI_CRCCALCULATION_DISABLE;
    SPI_InitStruct.CRCPoly = 7;
    LL_SPI_Init(SPI1, &SPI_InitStruct);

    LL_SPI_SetStandard(SPI1, LL_SPI_PROTOCOL_MOTOROLA);


}
