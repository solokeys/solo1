#include "sense.h"
#include "device.h"
#include "log.h"

#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_hal_tsc.h"

int _run_sense_app = 0;
static int _has_init = 0;


void sense_init()
{
    LL_GPIO_InitTypeDef GPIO_InitStruct1;
    LL_GPIO_InitTypeDef GPIO_InitStruct2;
    // Enable TSC clock
    RCC->AHB1ENR |= (1<<16);

    /** TSC GPIO Configuration
    PA4   ------> Channel 1
    PA5   ------> Channel 2
    */
    GPIO_InitStruct1.Pin = LL_GPIO_PIN_5|LL_GPIO_PIN_4;
    GPIO_InitStruct1.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct1.Speed = LL_GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct1.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    GPIO_InitStruct1.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct1.Alternate = LL_GPIO_AF_9;
    LL_GPIO_Init(GPIOB, &GPIO_InitStruct1);

    /** TSC GPIO Configuration
    PA6   ------> sampling cap
    */
    GPIO_InitStruct2.Pin = LL_GPIO_PIN_6;
    GPIO_InitStruct2.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct2.Speed = LL_GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct2.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
    GPIO_InitStruct2.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct2.Alternate = LL_GPIO_AF_9;
    LL_GPIO_Init(GPIOB, &GPIO_InitStruct2);

    // Channel IOs
    uint32_t channel_ios = TSC_GROUP2_IO1;

    // enable
    TSC->CR = TSC_CR_TSCE;

    TSC->CR |= (TSC_CTPH_16CYCLES |
                           TSC_CTPL_16CYCLES |
                           (uint32_t)(1 << TSC_CR_SSD_Pos) |
                           TSC_SS_PRESC_DIV1 |
                           TSC_PG_PRESC_DIV128 |
                           TSC_MCV_16383 |
                           TSC_SYNC_POLARITY_FALLING |
                           TSC_ACQ_MODE_NORMAL);

    // Spread spectrum
    if (0)
    {
      TSC->CR |= TSC_CR_SSE;
    }

    // Schmitt trigger and hysteresis
    TSC->IOHCR = (uint32_t)(~(channel_ios | 0 | TSC_GROUP2_IO3));

    // Channel IDs
    TSC->IOCCR = (channel_ios | 0);

    // Sampling IOs
    TSC->IOSCR = TSC_GROUP2_IO3;

    // Groups
    uint32_t grps = 0x02;
    TSC->IOGCSR = grps;

    TSC->IER &= (uint32_t)(~(TSC_IT_EOA | TSC_IT_MCE));
    TSC->ICR = (TSC_FLAG_EOA | TSC_FLAG_MCE);

}

void tsc_start_acq()
{
    TSC->CR &= ~(TSC_CR_START);

    TSC->ICR = TSC_FLAG_EOA | TSC_FLAG_MCE;

    // Set IO output to output push-pull low
    TSC->CR &= (~TSC_CR_IODEF);

    TSC->CR |= TSC_CR_START;
}

void tsc_wait_on_acq()
{
    while ( ! (TSC->ISR & TSC_FLAG_EOA) )
        ;
    if ( TSC->ISR & TSC_FLAG_MCE )
    {
        printf1(TAG_ERR,"Max count reached\r\n");
    }
}

uint32_t tsc_read(uint32_t indx)
{
    return TSC->IOGXCR[indx];
}

void sense_run()
{
    static uint32_t t1 = 0;
    uint32_t samp;

    if (!_has_init)
    {
        sense_init();
        _has_init = 1;
    }

    if ((millis() - t1) > 200)
    {
        tsc_start_acq();
        tsc_wait_on_acq();
        // delay(4);
        samp = tsc_read(1);

        printf1(TAG_GREEN, "sensing %02d %02d %02d %02d\r\n",
        tsc_read(0),
        tsc_read(1),
        tsc_read(2),
        tsc_read(3)
    );
        t1 = millis();
    }


}
