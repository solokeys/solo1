#include "sense.h"
#include "device.h"
#include "log.h"

#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_hal_tsc.h"

int _run_sense_app = 0;
static int _has_init = 0;

#define ELECTRODE_0     TSC_GROUP2_IO1
#define ELECTRODE_1     TSC_GROUP2_IO2

void tsc_init()
{
    LL_GPIO_InitTypeDef GPIO_InitStruct;
    // Enable TSC clock
    RCC->AHB1ENR |= (1<<16);

    /** TSC GPIO Configuration
    PA4   ------> Channel 1
    PA5   ------> Channel 2
    */
    GPIO_InitStruct.Pin = LL_GPIO_PIN_5|LL_GPIO_PIN_4;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct.Alternate = LL_GPIO_AF_9;
    LL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    /** TSC GPIO Configuration
    PA6   ------> sampling cap
    */
    GPIO_InitStruct.Pin = LL_GPIO_PIN_6;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_ALTERNATE;
    GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_LOW;
    GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
    GPIO_InitStruct.Pull = LL_GPIO_PULL_NO;
    GPIO_InitStruct.Alternate = LL_GPIO_AF_9;
    LL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    // Channel IOs
    uint32_t channel_ios = TSC_GROUP2_IO1 | TSC_GROUP2_IO2;

    // enable
    TSC->CR = TSC_CR_TSCE;

    TSC->CR |= (TSC_CTPH_8CYCLES |
                           TSC_CTPL_8CYCLES |
                           (uint32_t)(1 << TSC_CR_SSD_Pos) |
                           TSC_SS_PRESC_DIV1 |
                           TSC_PG_PRESC_DIV16 |
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

    // Sampling IOs
    TSC->IOSCR = TSC_GROUP2_IO3;

    // Groups
    uint32_t grps = 0x02;
    TSC->IOGCSR = grps;

    TSC->IER &= (uint32_t)(~(TSC_IT_EOA | TSC_IT_MCE));
    TSC->ICR = (TSC_FLAG_EOA | TSC_FLAG_MCE);

}

void tsc_set_electrode(uint32_t channel_ids)
{
    TSC->IOCCR = (channel_ids);
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

// Read button 0 or 1
// Returns 1 if pressed, 0 if not.
uint32_t tsc_read_button(uint32_t index)
{
    switch(index)
    {
        case 0:
            tsc_set_electrode(ELECTRODE_0);
            break;
        case 1:
            tsc_set_electrode(ELECTRODE_1);
            break;

    }
    tsc_start_acq();
    tsc_wait_on_acq();
    return tsc_read(1) < 50;
}

void sense_run()
{
    static uint32_t tlim = 0;
    uint32_t t1,t2;
    uint32_t but0,but1;

    if (!_has_init)
    {
        tsc_init();
        _has_init = 1;
    }

    if ((millis() - tlim) > 200)
    {
        t1 = millis();
        but0 = tsc_read_button(0);
        but1 = tsc_read_button(1);
        t2 = millis();

        printf1(TAG_GREEN, "but0: %02d but1: %02d (%d ms)\r\n",  but0, but1, t2-t1);
        t1 = millis();

        tlim  = millis();
    }
}
