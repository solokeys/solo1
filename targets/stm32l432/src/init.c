/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 *
 * This file is part of Solo.
 *
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 *
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
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
#include "stm32l4xx_hal_pcd.h"
#include "stm32l4xx_hal.h"

#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_hid.h"
#include "usbd_cdc.h"
#include "usbd_composite.h"
#include "usbd_cdc_if.h"
#include "device.h"
#include APP_CONFIG

/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private variables ---------------------------------------------------------*/

USBD_HandleTypeDef Solo_USBD_Device;

/* Private function prototypes -----------------------------------------------*/
static void LL_Init(void);
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_TIM2_Init(void);
static void MX_TIM6_Init(void);
static void MX_RNG_Init(void);
static void MX_SPI1_Init(void);

#define Error_Handler() _Error_Handler(__FILE__,__LINE__)
void _Error_Handler(char *file, int line);


void hw_init(void)
{
#ifdef IS_BOOTLOADER
    SCB->VTOR = FLASH_BASE;
#else
#endif
    LL_Init();

    SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_PWREN);

    SystemClock_Config(); // TODO bootloader should not change clk freq.

    MX_GPIO_Init();
    MX_TIM2_Init();       // PWM for LEDs

    MX_TIM6_Init();       // ~1 ms timer


#if DEBUG_LEVEL > 0
    MX_USART1_UART_Init();// debug uart
#endif

    MX_RNG_Init();
    MX_SPI1_Init();
    TIM6->SR = 0;
    __enable_irq();
    NVIC_EnableIRQ(TIM6_IRQn);
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
static int NFC = 0;
/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
    if (!NFC)
    {

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
    else
    {
        LL_FLASH_SetLatency(LL_FLASH_LATENCY_0);

        if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_0)
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
    }

}

void usb_init()
{
    if (!NFC)
    {
        // enable USB power
        SET_BIT(PWR->CR2, PWR_CR2_USV);

        // Enable USB Clock
        SET_BIT(RCC->APB1ENR1, RCC_APB1ENR1_USBFSEN);


        USBD_Composite_Set_Classes(&USBD_HID, &USBD_CDC);
        in_endpoint_to_class[HID_EPIN_ADDR & 0x7F] = 0;
        out_endpoint_to_class[HID_EPOUT_ADDR & 0x7F] = 0;

        in_endpoint_to_class[CDC_IN_EP & 0x7F] = 1;
        out_endpoint_to_class[CDC_OUT_EP & 0x7F] = 1;

        USBD_Init(&Solo_USBD_Device, &Solo_Desc, 0);
        USBD_RegisterClass(&Solo_USBD_Device, &USBD_Composite);
        // USBD_RegisterClass(&Solo_USBD_Device, &USBD_HID);
        //
        // USBD_RegisterClass(&Solo_USBD_Device, &USBD_CDC);
        USBD_CDC_RegisterInterface(&Solo_USBD_Device, &USBD_Interface_fops_FS);

        USBD_Start(&Solo_USBD_Device);
    }
}

/* TIM2 init function */
static void MX_TIM2_Init(void)
{
    // if(!NFC)
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

}

/* USART1 init function */
static void MX_USART1_UART_Init(void)
{

  LL_USART_InitTypeDef USART_InitStruct;

  LL_GPIO_InitTypeDef GPIO_InitStruct;

  /* Peripheral clock enable */
  LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_USART1);

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

/** Pinout Configuration
*/
static void MX_GPIO_Init(void)
{

  /* GPIO Ports Clock Enable */
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_GPIOA);
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_GPIOB);

}


/* TIM6 init function */
static void MX_TIM6_Init(void)
{

    LL_TIM_InitTypeDef TIM_InitStruct;

    /* Peripheral clock enable */
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_TIM6);

    // 48 MHz sys clock --> 6 MHz timer clock
    // 48 MHz / 48000 == 1000 Hz
    if (!NFC)
        TIM_InitStruct.Prescaler = 48000;
    else
        TIM_InitStruct.Prescaler = 4000;

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
}

/* TIM7 init function */
// static void MX_TIM7_Init(void)
// {
//
//   LL_TIM_InitTypeDef TIM_InitStruct;
//
//   /* Peripheral clock enable */
//   LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_TIM7);
//
//   // 48 MHz sys clock --> 6 MHz timer clock
//   // 6 MHz / 6000 == 1000 Hz
//   TIM_InitStruct.Prescaler = 48000;
//   TIM_InitStruct.CounterMode = LL_TIM_COUNTERMODE_UP;
//   TIM_InitStruct.Autoreload = 0xffff;
//   LL_TIM_Init(TIM6, &TIM_InitStruct);
//
//   LL_TIM_DisableARRPreload(TIM7);
//
//   LL_TIM_SetTriggerOutput(TIM7, LL_TIM_TRGO_RESET);
//
//   LL_TIM_DisableMasterSlaveMode(TIM7);
//
//   // enable interrupt
//   TIM7->DIER |= 1;
//
//   // Start immediately
//   LL_TIM_EnableCounter(TIM7);
// }

/* RNG init function */
static void MX_RNG_Init(void)
{

  /* Peripheral clock enable */
  LL_AHB2_GRP1_EnableClock(LL_AHB2_GRP1_PERIPH_RNG);

  LL_RNG_Enable(RNG);

}

/* SPI1 init function */
static void MX_SPI1_Init(void)
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
    // if (!NFC)
    //     SPI_InitStruct.BaudRate = LL_SPI_BAUDRATEPRESCALER_DIV64;
    // else
        SPI_InitStruct.BaudRate = LL_SPI_BAUDRATEPRESCALER_DIV2;
    SPI_InitStruct.BitOrder = LL_SPI_MSB_FIRST;
    SPI_InitStruct.CRCCalculation = LL_SPI_CRCCALCULATION_DISABLE;
    SPI_InitStruct.CRCPoly = 7;
    LL_SPI_Init(SPI1, &SPI_InitStruct);

    LL_SPI_SetStandard(SPI1, LL_SPI_PROTOCOL_MOTOROLA);

    // LL_SPI_EnableNSSPulseMgt(SPI1);


}
