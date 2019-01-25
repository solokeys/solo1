#include <string.h>

#include "stm32l4xx.h"

#include "nfc.h"
#include "ams.h"
#include "log.h"
#include "util.h"
#include "device.h"

#include "ctap_errors.h"


// Capability container


const CAPABILITY_CONTAINER NFC_CC = {
    .cclen_hi = 0x00, .cclen_lo = 0x0f,
    .version = 0x01,
    .MLe_hi = 0x00, .MLe_lo = 0xff,
    .MLc_hi = 0x00, .MLc_lo = 0xff,
    .tlv = { 0x04,0x06,
            0x11,0x11,
            0x00,0xff,
            0x00,0xff }
};

uint8_t NDEF_SAMPLE[] = "\x00\x13\xD1\x01\x0ET\x02enHello World";

static struct
{
    uint8_t max_frame_size;
    uint8_t cid;
    uint8_t block_num;
    uint8_t selected_applet;
} NFC_STATE;

void nfc_state_init()
{
    memset(&NFC_STATE,0,sizeof(NFC_STATE));
    NFC_STATE.max_frame_size = 32;
    NFC_STATE.block_num = 1;
}

void nfc_init()
{
    nfc_state_init();
    ams_init();
}
void process_int0(uint8_t int0)
{
	
}

bool ams_wait_for_tx(uint32_t timeout_ms)
{
	uint32_t tstart = millis();
	while (tstart + timeout_ms > millis())
	{
		uint8_t int0 = ams_read_reg(AMS_REG_INT0);
		if (int0) process_int0(int0);
		if (int0 & AMS_INT_TXE)
			return true;

		delay(1);
	}
	
	return false;
}

//bool ams_receive_with_timeout(10, recbuf, sizeof(recbuf), &reclen))
bool ams_receive_with_timeout(uint32_t timeout_ms, uint8_t * data, int maxlen, int *dlen)
{
	uint8_t buf[32];
	*dlen = 0;
	
	uint32_t tstart = millis();
	while (tstart + timeout_ms > millis())
	{
		uint8_t int0 = ams_read_reg(AMS_REG_INT0);
		uint8_t buffer_status2 = ams_read_reg(AMS_REG_BUF2);
		
        if (buffer_status2 && (int0 & AMS_INT_RXE))
        {
            if (buffer_status2 & AMS_BUF_INVALID)
            {
                printf1(TAG_NFC,"Buffer being updated!\r\n");
            }
            else
            {
                uint8_t len = buffer_status2 & AMS_BUF_LEN_MASK;
                ams_read_buffer(buf, len);
				printf1(TAG_NFC,">> "); dump_hex1(TAG_NFC, buf, len);

				*dlen = MIN(32, MIN(maxlen, len));
				memcpy(data, buf, *dlen);

				return true;
            }
        }
		
		delay(1);
	}
	
	return false;
}

void nfc_write_frame(uint8_t * data, uint8_t len)
{
    if (len > 32)
    {
        len = 32;
    }
    ams_write_command(AMS_CMD_CLEAR_BUFFER);
    ams_write_buffer(data,len);
    ams_write_command(AMS_CMD_TRANSMIT_BUFFER);

    printf1(TAG_NFC,"<< "); dump_hex1(TAG_NFC, data, len);
}

bool nfc_write_response_ex(uint8_t req0, uint8_t * data, uint8_t len, uint16_t resp)
{
    uint8_t res[32];

	if (len > 32 - 3)
		return false;
	
	res[0] = NFC_CMD_IBLOCK | (req0 & 3);
	
	if (len && data)
		memcpy(&res[1], data, len);
	
	res[len + 1] = resp >> 8;
	res[len + 2] = resp & 0xff;
	nfc_write_frame(res, 3 + len);
	
	return true;
}

bool nfc_write_response(uint8_t req0, uint16_t resp)
{
	return nfc_write_response_ex(req0, NULL, 0, resp);
}

void nfc_write_response_chaining(uint8_t req0, uint8_t * data, int len, uint16_t resp)
{
    uint8_t res[32 + 2];
	int sendlen = 0;
	uint8_t iBlock = NFC_CMD_IBLOCK | (req0 & 3);
printf1(TAG_NFC,"-- chain \r\n");
	if (len <= 32)
	{
		nfc_write_response_ex(req0, data, len, resp);
	} else {
		do {
			// transmit I block
			int vlen = MIN(31, len - sendlen);
			res[0] = iBlock;
			memcpy(&res[1], &data[sendlen], vlen);
			if (vlen + sendlen < len) 
			{
				res[0] |= 0x10;
			} else {
				// here may be buffer overflow!!!
				res[vlen + 1] = resp >> 8;
				res[vlen + 2] = resp & 0xff;
				vlen += 2;
			}

			nfc_write_frame(res, vlen + 1);
			sendlen += vlen;
			
			printf1(TAG_NFC,"-- slen: %d res0: %02x\r\n", sendlen, res[0]);
			
			// wait for transmit (32 bytes aprox 2,5ms)
			if (!ams_wait_for_tx(10))
			{
				printf1(TAG_NFC, "TX timeout. slen: %d \r\n", sendlen);
				break;
			}
			
			// receive R block
			if (res[0] & 0x10)
			{
				uint8_t recbuf[32] = {0};
				int reclen;
				if (!ams_receive_with_timeout(100, recbuf, sizeof(recbuf), &reclen))
				{
					printf1(TAG_NFC, "R block RX timeout.\r\n");
					break;
				}
				
				if (reclen != 1)
				{
					printf1(TAG_NFC, "R block length error. len: %d \r\n", reclen);
					break;
				}

				if (((recbuf[0] & 0x01) != (res[0] & 1)) && ((recbuf[0] & 0xf6) == 0xa2))
				{
					printf1(TAG_NFC, "R block error. txdata: %02x rxdata: %02x \r\n", res[0], recbuf[0]);
					//break;
				}
			}
			
			iBlock ^= 0x01;
		} while (sendlen < len);
	}
}

int answer_rats(uint8_t parameter)
{

    uint8_t fsdi = (parameter & 0xf0) >> 4;
    uint8_t cid = (parameter & 0x0f);

    NFC_STATE.cid = cid;

    if (fsdi == 0)
        NFC_STATE.max_frame_size = 16;
    else if (fsdi == 1)
        NFC_STATE.max_frame_size = 24;
    else
        NFC_STATE.max_frame_size = 32;

    uint8_t res[3 + 11];
    res[0] = sizeof(res);
    res[1] = 2 | (1<<5);     // 2 FSCI == 32 byte frame size, TB is enabled

    // frame wait time = (256 * 16 / 13.56MHz) * 2^FWI
    // FWI=0, FMT=0.3ms (min)
    // FWI=4, FMT=4.8ms (default)
    // FWI=10, FMT=309ms
    // FWI=12, FMT=1237ms
    // FWI=14, FMT=4949ms (max)
    res[2] = (12<<4) | (0);     // TB (FWI << 4) | (SGTI)

	// historical bytes
	memcpy(&res[3], (uint8_t *)"SoloKey tap", 11);
	
    nfc_write_frame(res, sizeof(res));
    return 0;
}

void rblock_acknowledge()
{
    uint8_t buf[32];
    NFC_STATE.block_num = !NFC_STATE.block_num;
    buf[0] = NFC_CMD_RBLOCK | NFC_STATE.block_num;
    nfc_write_frame(buf,1);
}

// Selects application.  Returns 1 if success, 0 otherwise
int select_applet(uint8_t * aid, int len)
{
    if (memcmp(aid,AID_FIDO,sizeof(AID_FIDO)) == 0)
    {
        NFC_STATE.selected_applet = APP_FIDO;
        return 1;
    }
    return 0;
}

void nfc_process_iblock(uint8_t * buf, int len)
{
    APDU_HEADER * apdu = (APDU_HEADER *)(buf + 1);
    uint8_t * payload = buf + 1 + 5;
    uint8_t plen = apdu->lc;
    int selected;
    uint8_t res[32];

    CTAP_RESPONSE ctap_resp;	
    int status;
	
    printf1(TAG_NFC,">> "); 
	dump_hex1(TAG_NFC, buf, len);

    // TODO this needs to be organized better
    switch(apdu->ins)
    {
        case APDU_INS_SELECT:
            if (plen > len - 6)
            {
                printf1(TAG_ERR, "Truncating APDU length %d\r\n", apdu->lc);
                plen = len-6;
            }
            // if (apdu->p1 == 0 && apdu->p2 == 0x0c)
            // {
            //     printf1(TAG_NFC,"Select NDEF\r\n");
            //
            //     NFC_STATE.selected_applet = APP_NDEF_TAG;
            //     // Select NDEF file!
            //     res[0] = NFC_CMD_IBLOCK | (buf[0] & 1);
            //     res[1] = SW_SUCCESS>>8;
            //     res[2] = SW_SUCCESS & 0xff;
            //     nfc_write_frame(res, 3);
            //     printf1(TAG_NFC,"<< "); dump_hex1(TAG_NFC,res, 3);
            // }
            // else
            {
                selected = select_applet(payload, plen);
                if (selected)
                {
                    // block = buf[0] & 1;
                    // block = NFC_STATE.block_num;
                    // block = !block;
                    // NFC_STATE.block_num = block;
					nfc_write_response_ex(buf[0], (uint8_t *)"U2F_V2", 6, SW_SUCCESS);
                }
                else
                {
					nfc_write_response(buf[0], SW_FILE_NOT_FOUND);
                    printf1(TAG_NFC, "NOT selected\r\n"); dump_hex1(TAG_NFC,res, 3);
                }
            }
        break;

        case APDU_FIDO_U2F_VERSION:
			printf1(TAG_NFC, "U2F GetVersion command.\r\n");

			nfc_write_response_ex(buf[0], (uint8_t *)"U2F_V2", 6, SW_SUCCESS);
        break;

        case APDU_FIDO_U2F_REGISTER:
			printf1(TAG_NFC, "U2F Register command.\r\n");

			nfc_write_response(buf[0], SW_COND_USE_NOT_SATISFIED);
        break;

        case APDU_FIDO_U2F_AUTHENTICATE:
			printf1(TAG_NFC, "U2F Authenticate command.\r\n");
			
			nfc_write_response(buf[0], SW_COND_USE_NOT_SATISFIED);
        break;

        case APDU_FIDO_NFCCTAP_MSG:
			printf1(TAG_NFC, "FIDO2 CTAP message.\r\n");
			
            ctap_response_init(&ctap_resp);
            status = ctap_request(payload, plen, &ctap_resp);
			printf1(TAG_NFC, "CTAP resp: %d  len: %d\r\n", status, ctap_resp.length);
			
			if (status == CTAP1_ERR_SUCCESS) 
			{
				uint8_t ctapdata[1024] = {0};
				ctapdata[0] = status;
				memcpy(&ctapdata[1], ctap_resp.data, ctap_resp.length);
				nfc_write_response_chaining(buf[0], ctapdata, ctap_resp.length + 1, SW_SUCCESS);
			} else {
				nfc_write_response(buf[0], SW_INTERNAL_EXCEPTION | status);
			}
        break;

        case APDU_INS_READ_BINARY:


            switch(NFC_STATE.selected_applet)
            {
                case APP_CAPABILITY_CONTAINER:
                    printf1(TAG_NFC,"APP_CAPABILITY_CONTAINER\r\n");
                    if (plen > 15)
                    {
                        printf1(TAG_ERR, "Truncating requested CC length %d\r\n", apdu->lc);
                        plen = 15;
                    }
                    memmove(res+1, &NFC_CC, plen);
                break;
                case APP_NDEF_TAG:
                    printf1(TAG_NFC,"APP_NDEF_TAG\r\n");
                    if (plen > (sizeof(NDEF_SAMPLE) -  1))
                    {
                        printf1(TAG_ERR, "Truncating requested CC length %d\r\n", apdu->lc);
                        plen = sizeof(NDEF_SAMPLE) -  1;
                    }
                    memmove(res+1, NDEF_SAMPLE, plen);
                break;
                default:
                    printf1(TAG_ERR, "No binary applet selected!\r\n");
                    return;
                break;
            }
            res[0] = NFC_CMD_IBLOCK | (buf[0] & 1);

            res[1+plen] = SW_SUCCESS>>8;
            res[2+plen] = SW_SUCCESS & 0xff;
            nfc_write_frame(res, 3+plen);
            printf1(TAG_NFC,"APDU_INS_READ_BINARY\r\n");
            printf1(TAG_NFC,"<< "); dump_hex1(TAG_NFC,res, 3+plen);
        break;
        default:
            printf1(TAG_NFC, "Unknown INS %02x\r\n", apdu->ins);
			nfc_write_response(buf[0], SW_INS_INVALID);
        break;
    }


}

void nfc_process_block(uint8_t * buf, int len)
{
    if (IS_PPSS_CMD(buf[0]))
    {
        printf1(TAG_NFC, "NFC_CMD_PPSS\r\n");
    }
    else if (IS_IBLOCK(buf[0]))
    {
        printf1(TAG_NFC, "NFC_CMD_IBLOCK\r\n");
        nfc_process_iblock(buf, len);
    }
    else if (IS_RBLOCK(buf[0]))
    {
        rblock_acknowledge();
        printf1(TAG_NFC, "NFC_CMD_RBLOCK\r\n");
    }
    else if (IS_SBLOCK(buf[0]))
    {

        if ((buf[0] & NFC_SBLOCK_DESELECT) == 0)
        {
            nfc_write_frame(buf, 1);
            printf1(TAG_NFC, "NFC_CMD_SBLOCK, DESELECTED\r\n");
            nfc_state_init();
        }
        else
        {
            printf1(TAG_NFC, "NFC_CMD_SBLOCK, Unknown\r\n");
        }
        dump_hex1(TAG_NFC, buf, len);
    }
    else
    {
        printf1(TAG_NFC, "unknown NFC request\r\n len[%d]:", len);
        dump_hex1(TAG_NFC, buf, len);
    }
}

void nfc_loop()
{
    static uint32_t t1 = 0;
    uint8_t buf[32];
    AMS_DEVICE ams;
    int len = 0;
    // uint8_t def[] = "\x00\x00\x05\x40\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x02\x01\x00";


    // if (millis() - t1 > interval)
    if (1)
    {
        t1 = millis();
        read_reg_block(&ams);
		
		process_int0(ams.regs.int0);
		
        // if (memcmp(def,ams.buf,sizeof(AMS_DEVICE)) != 0)
        // {
        //     printf1(TAG_NFC,"regs: "); dump_hex1(TAG_NFC,ams.buf,sizeof(AMS_DEVICE));
        // }
        if (ams.regs.rfid_status)
        {
            // uint8_t state = AMS_STATE_MASK & ams.regs.rfid_status;
            // if (state != AMS_STATE_SENSE)
            //     printf1(TAG_NFC,"    %s  %d\r\n", ams_get_state_string(ams.regs.rfid_status), millis());
        }
        if (ams.regs.int0 & AMS_INT_INIT)
        {
            // Initialize chip!
            nfc_state_init();
        }
        if (ams.regs.int1)
        {
            // ams_print_int1(ams.regs.int1);
        }
        if (ams.regs.buffer_status2 && (ams.regs.int0 & AMS_INT_RXE))
        {
            if (ams.regs.buffer_status2 & AMS_BUF_INVALID)
            {
                printf1(TAG_NFC,"Buffer being updated!\r\n");
            }
            else
            {
                len = ams.regs.buffer_status2 & AMS_BUF_LEN_MASK;
                ams_read_buffer(buf, len);
            }
        }

        if (len)
        {

            // ISO 14443-3
            switch(buf[0])
            {
                case NFC_CMD_REQA:
                    printf1(TAG_NFC, "NFC_CMD_REQA\r\n");
                break;
                case NFC_CMD_WUPA:
                    printf1(TAG_NFC, "NFC_CMD_WUPA\r\n");
                break;
                case NFC_CMD_HLTA:
                    printf1(TAG_NFC, "HLTA/Halt\r\n");
                break;
                case NFC_CMD_RATS:
                    t1 = millis();
                    answer_rats(buf[1]);
                    NFC_STATE.block_num = 1;
                    printf1(TAG_NFC,"RATS answered %d (took %d)\r\n",millis(), millis() - t1);
                break;
                default:

                    // ISO 14443-4
                    nfc_process_block(buf,len);


                break;
            }



        }
    }


}
