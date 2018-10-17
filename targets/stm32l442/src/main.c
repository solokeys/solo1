#include <stdint.h>
#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_rcc.h"
#include "stm32l4xx_ll_system.h"
#include "stm32l4xx_ll_pwr.h"
#include "stm32l4xx_ll_utils.h"
#include "stm32l4xx_ll_cortex.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_usart.h"
#include "stm32l4xx_ll_bus.h"

#define Error_Handler() _Error_Handler(__FILE__,__LINE__)

#define VCP_TX_Pin LL_GPIO_PIN_2
#define VCP_RX_Pin LL_GPIO_PIN_15
#define VCP_TX_GPIO_Port GPIOA
#define VCP_RX_GPIO_Port GPIOA

void _Error_Handler(char *file, int line);

void delay(uint32_t ms)
{
    volatile int x,y;
    for (x=0; x < 100; x++)
        for (y=0; y < ms * 20; y++)
            ;
}

void uart_write(USART_TypeDef *uart, uint8_t * data, uint32_t len)
{
    while(len--)
    {
        while (! LL_USART_IsActiveFlag_TXE(uart))
            ;
        LL_USART_TransmitData8(uart,*data++);
    }
}

void MX_USART2_UART_Init(void)
{

  LL_USART_InitTypeDef USART_InitStruct;

  LL_GPIO_InitTypeDef GPIO_InitStruct;

  /* Peripheral clock enable */
  LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_USART2);
  
  /**USART2 GPIO Configuration  
  PA2   ------> USART2_TX
  PA15 (JTDI)   ------> USART2_RX 
  */
  GPIO_InitStruct.Pin = VCP_TX_Pin;
  GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
  GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
  GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
  GPIO_InitStruct.Alternate = LL_GPIO_AF_7;
  LL_GPIO_Init(VCP_TX_GPIO_Port, &GPIO_InitStruct);

  GPIO_InitStruct.Pin = VCP_RX_Pin;
  GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
  GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
  GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
  GPIO_InitStruct.Alternate = LL_GPIO_AF_3;
  LL_GPIO_Init(VCP_RX_GPIO_Port, &GPIO_InitStruct);

  USART_InitStruct.BaudRate = 115200;
  USART_InitStruct.DataWidth = LL_USART_DATAWIDTH_8B;
  USART_InitStruct.StopBits = LL_USART_STOPBITS_1;
  USART_InitStruct.Parity = LL_USART_PARITY_NONE;
  USART_InitStruct.TransferDirection = LL_USART_DIRECTION_TX_RX;
  USART_InitStruct.HardwareFlowControl = LL_USART_HWCONTROL_NONE;
  USART_InitStruct.OverSampling = LL_USART_OVERSAMPLING_16;
  LL_USART_Init(USART2, &USART_InitStruct);

  LL_USART_ConfigAsyncMode(USART2);

  LL_USART_Enable(USART2);

}



// Generated via cube
void SystemClock_Config(void)
{

    LL_FLASH_SetLatency(LL_FLASH_LATENCY_2);

    if(LL_FLASH_GetLatency() != LL_FLASH_LATENCY_2)
    {
        Error_Handler();  
    }
    LL_PWR_SetRegulVoltageScaling(LL_PWR_REGU_VOLTAGE_SCALE1);

    LL_RCC_MSI_Enable();

    /* Wait till MSI is ready */
    while(LL_RCC_MSI_IsReady() != 1)
    {

    }
    LL_RCC_MSI_EnablePLLMode();

    LL_RCC_MSI_EnableRangeSelection();

    LL_RCC_MSI_SetRange(LL_RCC_MSIRANGE_11);

    LL_RCC_MSI_SetCalibTrimming(0);

    LL_PWR_EnableBkUpAccess();

    LL_RCC_LSE_SetDriveCapability(LL_RCC_LSEDRIVE_LOW);

    LL_RCC_LSE_Enable();

    /* Wait till LSE is ready */
    while(LL_RCC_LSE_IsReady() != 1)
    {

    }
    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_MSI);

    /* Wait till System clock is ready */
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_MSI)
    {

    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_16);

    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_16);

    LL_Init1msTick(48000000);

    LL_SYSTICK_SetClkSource(LL_SYSTICK_CLKSOURCE_HCLK);

    LL_SetSystemCoreClock(48000000);

    LL_RCC_SetUSARTClockSource(LL_RCC_USART2_CLKSOURCE_PCLK1);

    /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_GetPriorityGrouping(),0, 0));
}

#define LED_PIN     LL_GPIO_PIN_3
#define LED_PORT    GPIOB
void hw_init()
{

    SystemClock_Config();
    // initialize GPIO
    // Enable clock to A,B,C
    SET_BIT(RCC->AHB2ENR, RCC_AHB2ENR_GPIOAEN);
    SET_BIT(RCC->AHB2ENR, RCC_AHB2ENR_GPIOBEN);
    SET_BIT(RCC->AHB2ENR, RCC_AHB2ENR_GPIOCEN);
    LL_GPIO_SetPinMode(LED_PORT, LED_PIN, LL_GPIO_MODE_OUTPUT);
    /*  NVIC_SetPriorityGrouping(NVIC_PRIORITYGROUP_4);*/
    /*SystemClock_Config();*/


    MX_USART2_UART_Init();
}

int main(void)
{
    uint8_t msg[] = "hi  !\r\n";
    int i = 'A';
    hw_init();

    while (1)
    {
        LL_GPIO_TogglePin(LED_PORT, LED_PIN);
        delay(500);
        msg[3] = i++;
        uart_write(USART2, msg, sizeof(msg));
    }
}

void _Error_Handler(char *file, int line)
{

    while(1)
    {
    }
}

