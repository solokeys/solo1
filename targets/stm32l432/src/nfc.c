#include <string.h>

#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_spi.h"
#include "nfc.h"
#include "log.h"
#include "util.h"


static void flush_rx()
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) != 0)
    {
        LL_SPI_ReceiveData8(SPI1);
    }
}
static void wait_for_tx()
{
    // while (LL_SPI_IsActiveFlag_BSY(SPI1) == 1)
    //     ;
    while(LL_SPI_GetTxFIFOLevel(SPI1) != LL_SPI_TX_FIFO_EMPTY)
        ;
}
static void wait_for_rx()
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) == 0)
        ;
}


#define SELECT() LL_GPIO_ResetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)
#define UNSELECT() LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)

uint8_t send_recv(uint8_t b)
{
    wait_for_tx();
    LL_SPI_TransmitData8(SPI1, b);
    wait_for_rx();
    b  = LL_SPI_ReceiveData8(SPI1);
    return b;
}

uint8_t send_recv2(uint8_t b1,uint8_t b2)
{
    send_recv(b1);
    return send_recv(b2);
}

void ams_write_reg(uint8_t addr, uint8_t tx)
{
    // SELECT();
    // delay(2);
    send_recv(0x00| addr);
    send_recv(tx);

    UNSELECT();
    SELECT();
}


uint8_t ams_read_reg(uint8_t addr)
{
	// SELECT();
    // delay(2);

    uint8_t data = send_recv2(0x20| (addr & 0x1f), 0);
    // send_recv(0x20| addr);
    //
    // uint8_t data = send_recv(0);

    // delay(2);
    UNSELECT();
    SELECT();
    return data;
}

// data must be 14 bytes long
void read_reg_block2(uint8_t * data)
{
	int i;

	for (i = 0; i < 0x20; i++)
	{
		// if (i < 6 || (i >=8 && i < 0x0f) || (i >= 0x1e))
		{
			*data = ams_read_reg(i);
			data++;
		}
	}

}


// data must be 14 bytes long
void read_reg_block(uint8_t * data)
{
	int i;
	uint8_t mode = 0x20 | (0 );
    flush_rx();
	// SELECT();
    // delay(2);

	send_recv(mode);
	for (i = 0; i < 0x20; i++)
	{
		mode = send_recv(0);
		// if (i < 6 || (i >=8 && i < 0x0f) || (i >= 0x1e))
		// {
			*data = mode;
			data++;
		// }
	}

    UNSELECT();
    SELECT();
	// UNSELECT();
    // delay(2);
	// SELECT();
}

void ams_write_command(uint8_t cmd)
{

	uint8_t mode = cmd;
	// delay(10);

	// delay(10);
	SELECT();
	delay(1);
	send_recv(mode);
    UNSELECT();
	SELECT();

}

void nfc_init()
{
    LL_GPIO_SetPinMode(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN,LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);

    LL_SPI_SetClockPolarity(SPI1,LL_SPI_POLARITY_LOW);
    LL_SPI_SetClockPhase(SPI1,LL_SPI_PHASE_2EDGE);
    LL_SPI_SetRxFIFOThreshold(SPI1,LL_SPI_RX_FIFO_TH_QUARTER);
    LL_SPI_Enable(SPI1);
}

void nfc_loop()
{

        static int run = 0;

        if (!run)
        {
            uint8_t regs[0x20];
            run = 1;

            delay(10);
        	LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);
        	delay(10);
        	// LL_GPIO_ResetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);
        	delay(10);
            SELECT();
            delay(10);
            // ams_write_command(0xC2);				// Set to default state
            // ams_write_command(0xC4);				// Clear buffer
            ams_write_reg(2,7);
            int x;
            for (x = 0 ; x < 10; x++)
            {
                memset(regs,0,sizeof(regs));
                // ams_write_reg(1,7);
                read_reg_block(regs);
                printf1(TAG_NFC,"regs: "); dump_hex1(TAG_NFC,regs,sizeof(regs));


            }
            printf1(TAG_NFC,"---\r\n");
            for (x = 0 ; x < 10; x++)
            {
                memset(regs,0,sizeof(regs));
                read_reg_block2(regs);
                printf1(TAG_NFC,"regs: "); dump_hex1(TAG_NFC,regs,sizeof(regs));
            }

            printf1(TAG_NFC,"Version: %02x\r\n",ams_read_reg(0x1e));
            printf1(TAG_NFC,"Product Type: %02x\r\n",ams_read_reg(0x1c));

            //
            // LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);
            //
            // memset(regs,0,sizeof(regs));
            // for (x = 0 ; x < sizeof(regs); x++)
            // {
            //     regs[x] = ams_read_reg(x);
            // }
            // printf1(TAG_NFC,"regs2: "); dump_hex1(TAG_NFC,regs,sizeof(regs));
        }
}
