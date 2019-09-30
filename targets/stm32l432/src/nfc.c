#include <string.h>

#include "stm32l4xx.h"

#include "nfc.h"
#include "ams.h"
#include "log.h"
#include "util.h"
#include "device.h"
#include "u2f.h"
#include "crypto.h"

#include "ctap_errors.h"

#define IS_IRQ_ACTIVE()         (1  == (LL_GPIO_ReadInputPort(SOLO_AMS_IRQ_PORT) & SOLO_AMS_IRQ_PIN))

// chain buffer for 61XX responses
static uint8_t chain_buffer[2048] = {0};
static size_t chain_buffer_len = 0;
static bool chain_buffer_tx = false;
static uint8_t current_cid = 0;

// forward declarations
void rblock_acknowledge(uint8_t req0, bool ack);

uint8_t p14443_have_cid(uint8_t pcb) {
    // CID 
    if (pcb & 0x08)
        return true;
    else
        return false;
}

uint8_t p14443_block_offset(uint8_t pcb) {
    uint8_t offset = 1;
    // NAD following
    if (pcb & 0x04) offset++;
    // CID following
    if (pcb & 0x08) offset++;
    
    return offset;
}

// Capability container
const CAPABILITY_CONTAINER NFC_CC = {
    .cclen_hi = 0x00, .cclen_lo = 0x0f,
    .version = 0x20,
    .MLe_hi = 0x00, .MLe_lo = 0x7f,
    .MLc_hi = 0x00, .MLc_lo = 0x7f,
    .tlv = { 0x04,0x06,
            0xe1,0x04,
            0x00,0x7f,
            0x00,0x00 }
};

// 13 chars
uint8_t NDEF_SAMPLE[] = "\x00\x14\xd1\x01\x0eU\x04solokeys.com/";

// Poor way to get some info while in passive operation
#include <stdarg.h>
void nprintf(const char *format, ...)
{
    memmove((char*)NDEF_SAMPLE + sizeof(NDEF_SAMPLE) - 1 - 13,"             ", 13);
    va_list args;
    va_start (args, format);
    vsnprintf ((char*)NDEF_SAMPLE + sizeof(NDEF_SAMPLE) - 1 - 13, 13, format, args);
    va_end (args);
}

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

int nfc_init()
{
    uint32_t t1;
    int init;
    nfc_state_init();
    init = ams_init();

    // Detect if we are powered by NFC field by listening for a message for
    // first 10 ms.
    t1 = millis();
    while ((millis() - t1) < 10)
    {
        if (nfc_loop() > 0)
            return NFC_IS_ACTIVE;
    }

    // Under USB power.  Configure AMS chip.
    ams_configure();

    if (init)
    {
        return NFC_IS_AVAILABLE;
    }

    return NFC_IS_NA;
}

static uint8_t gl_int0 = 0;
void process_int0(uint8_t int0)
{
    gl_int0 = int0;
}

bool ams_wait_for_tx(uint32_t timeout_ms)
{
    if (gl_int0 & AMS_INT_TXE) {
		uint8_t int0 = ams_read_reg(AMS_REG_INT0);
		process_int0(int0);
        
        return true;
    }
    
	uint32_t tstart = millis();
	while (tstart + timeout_ms > millis())
	{
		uint8_t int0 = ams_read_reg(AMS_REG_INT0);
		process_int0(int0);
		if (int0 & AMS_INT_TXE || int0 & AMS_INT_RXE)
			return true;

		delay(1);
	}

	return false;
}

bool ams_receive_with_timeout(uint32_t timeout_ms, uint8_t * data, int maxlen, int *dlen)
{
	uint8_t buf[32];
	*dlen = 0;

	uint32_t tstart = millis();
	while (tstart + timeout_ms > millis())
	{
        uint8_t int0 = 0;
        if (gl_int0 & AMS_INT_RXE) {
            int0 = gl_int0;
        } else {
            int0 = ams_read_reg(AMS_REG_INT0);
            process_int0(int0);
        }
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
				printf1(TAG_NFC_APDU, ">> ");
				dump_hex1(TAG_NFC_APDU, buf, len);

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

    printf1(TAG_NFC_APDU, "<< ");
	dump_hex1(TAG_NFC_APDU, data, len);
}

bool nfc_write_response_ex(uint8_t req0, uint8_t * data, uint8_t len, uint16_t resp)
{
    uint8_t res[32];

	if (len > 32 - 3)
		return false;

	res[0] = NFC_CMD_IBLOCK | (req0 & 0x0f);
    res[1] = current_cid;
    res[2] = 0;

    uint8_t block_offset = p14443_block_offset(req0);

	if (len && data)
		memcpy(&res[block_offset], data, len);

	res[len + block_offset + 0] = resp >> 8;
	res[len + block_offset + 1] = resp & 0xff;
    
	nfc_write_frame(res, block_offset + len + 2);
    
    if (!ams_wait_for_tx(1))
    {
        printf1(TAG_NFC, "TX resp timeout. len: %d \r\n", len);
        return false;
    }

	return true;
}

bool nfc_write_response(uint8_t req0, uint16_t resp)
{
	return nfc_write_response_ex(req0, NULL, 0, resp);
}

void nfc_write_response_chaining_plain(uint8_t req0, uint8_t * data, int len)
{
    uint8_t res[32 + 2];
	uint8_t iBlock = NFC_CMD_IBLOCK | (req0 & 0x0f);
    uint8_t block_offset = p14443_block_offset(req0);

	if (len <= 31)
	{
		uint8_t res[32] = {0};
        res[0] = iBlock;
        res[1] = current_cid;
        res[2] = 0;
		if (len && data)
			memcpy(&res[block_offset], data, len);
		nfc_write_frame(res, len + block_offset);
	} else {
        int sendlen = 0;
		do {
			// transmit I block
			int vlen = MIN(32 - block_offset, len - sendlen);
            res[0] = iBlock;
            res[1] = current_cid;
            res[2] = 0;
			memcpy(&res[block_offset], &data[sendlen], vlen);

			// if not a last block
			if (vlen + sendlen < len)
			{
				res[0] |= 0x10;
			}

			// send data
			nfc_write_frame(res, vlen + block_offset);
			sendlen += vlen;

			// wait for transmit (32 bytes aprox 2,5ms)
			 if (!ams_wait_for_tx(5))
			 {
			 	printf1(TAG_NFC, "TX timeout. slen: %d \r\n", sendlen);
			 	break;
			 }

			// if needs to receive R block (not a last block)
			if (res[0] & 0x10)
			{
				uint8_t recbuf[32] = {0};
				int reclen;
				if (!ams_receive_with_timeout(100, recbuf, sizeof(recbuf), &reclen))
				{
					printf1(TAG_NFC, "R block RX timeout %d/%d.\r\n",sendlen,len);
					break;
				}
                
                if (!IS_RBLOCK(recbuf[0]))
                {
					printf1(TAG_NFC, "R block RX error. Not a R block(0x%02x) %d/%d.\r\n", recbuf[0], sendlen, len);
					break;
				}
                
                // NAK check
                if (recbuf[0] & NFC_CMD_RBLOCK_ACK)
                {
                    rblock_acknowledge(recbuf[0], true);
					printf1(TAG_NFC, "R block RX error. NAK received. %d/%d.\r\n", recbuf[0], sendlen, len);
					break;
                }

                uint8_t rblock_offset = p14443_block_offset(recbuf[0]);
				if (reclen != rblock_offset)
				{
					printf1(TAG_NFC, "R block length error. len: %d. %d/%d \r\n", reclen, sendlen, len);
                    dump_hex1(TAG_NFC, recbuf, reclen);
					break;
				}

				if (((recbuf[0] & 0x01) == (res[0] & 1)) && ((recbuf[0] & 0xf6) == 0xa2))
				{
					printf1(TAG_NFC, "R block error. txdata: %02x rxdata: %02x \r\n", res[0], recbuf[0]);
					break;
				}
			}

			iBlock ^= 0x01;
		} while (sendlen < len);
	}
}

void append_get_response(uint8_t *data, size_t rest_len)
{
    data[0] = 0x61;
    data[1] = 0x00;
    if (rest_len <= 0xff)
        data[1] = rest_len & 0xff;
}

void nfc_write_response_chaining(uint8_t req0, uint8_t * data, int len, bool extapdu)
{
    chain_buffer_len = 0;
    chain_buffer_tx = true;
    
    // if we dont need to break data to parts that need to exchange via GET RESPONSE command (ISO 7816-4 7.1.3)
	if (len <= 255 || extapdu)
    {
        nfc_write_response_chaining_plain(req0, data, len);
    } else {
        size_t pcklen = MIN(253, len);
        chain_buffer_len = len - pcklen;
        printf1(TAG_NFC, "61XX chaining %d/%d.\r\n", pcklen, chain_buffer_len);
        
        memmove(chain_buffer, data, pcklen);
        append_get_response(&chain_buffer[pcklen], chain_buffer_len);
       
        nfc_write_response_chaining_plain(req0, chain_buffer, pcklen + 2); // 2 for 61XX 
    
        // put the rest data into chain buffer
        memmove(chain_buffer, &data[pcklen], chain_buffer_len);        
    }    
}

// WTX on/off:
// sends/receives WTX frame to reader every `WTX_time` time in ms
// works via timer interrupts
// WTX: f2 01 91 40 === f2(S-block + WTX, frame without CID) 01(from iso - multiply WTX from ATS by 1) <2b crc16>
static bool WTX_sent;
static bool WTX_fail;
static uint32_t WTX_timer;

bool WTX_process(int read_timeout);

void WTX_clear(void)
{
	WTX_sent = false;
	WTX_fail = false;
	WTX_timer = 0;
}

bool WTX_on(int WTX_time)
{
	WTX_clear();
	WTX_timer = millis();

	return true;
}

bool WTX_off(void)
{
	WTX_timer = 0;

	// read data if we sent WTX
	if (WTX_sent)
	{
		if (!WTX_process(100))
		{
			printf1(TAG_NFC, "WTX-off get last WTX error\n");
			return false;
		}
	}

	if (WTX_fail)
	{
		printf1(TAG_NFC, "WTX-off fail\n");
		return false;
	}

	WTX_clear();
	return true;
}

void WTX_timer_exec(void)
{
	// condition: (timer on) or (not expired[300ms])
	if ((WTX_timer == 0) || WTX_timer + 300 > millis())
		return;

	WTX_process(10);
	WTX_timer = millis();
}

// executes twice a period. 1st for send WTX, 2nd for check the result
// read timeout must be 10 ms to call from interrupt
bool WTX_process(int read_timeout)
{
	if (WTX_fail)
		return false;

	if (!WTX_sent)
	{
        uint8_t wtx[] = {0xf2, 0x01};
		nfc_write_frame(wtx, sizeof(wtx));
		WTX_sent = true;
		return true;
	}
	else
	{
		uint8_t data[32];
		int len;
		if (!ams_receive_with_timeout(read_timeout, data, sizeof(data), &len))
		{
			WTX_fail = true;
			return false;
		}

		if (len != 2 || data[0] != 0xf2 || data[1] != 0x01)
		{
			WTX_fail = true;
			return false;
		}

		WTX_sent = false;
		return true;
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
	if (!ams_wait_for_tx(10))
	{
		printf1(TAG_NFC, "RATS TX timeout.\r\n");
		ams_write_command(AMS_CMD_DEFAULT);
		return 1;
	}


    return 0;
}

void rblock_acknowledge(uint8_t req0, bool ack)
{
    uint8_t buf[32] = {0};

    uint8_t block_offset = p14443_block_offset(req0);
    NFC_STATE.block_num = !NFC_STATE.block_num;

    buf[0] = NFC_CMD_RBLOCK | (req0 & 0x0f);
    buf[1] = current_cid;
    // iso14443-4:2001 page 16. ACK, if bit is set to 0, NAK, if bit is set to 1
    if (!ack)
        buf[0] |= NFC_CMD_RBLOCK_ACK;

    nfc_write_frame(buf, block_offset);
}

// international AID = RID:PIX
// RID length == 5 bytes
// usually aid length must be between 5 and 16 bytes
int applet_cmp(uint8_t * aid, int len, uint8_t * const_aid, int const_len)
{
    if (len > const_len)
        return 10;
    
    // if international AID
    if ((const_aid[0] & 0xf0) == 0xa0)
    {
        if (len < 5)
            return 11;
        return memcmp(aid, const_aid, MIN(len, const_len));
    } else {
        if (len != const_len)
            return 11;
        
        return memcmp(aid, const_aid, const_len);
    }
}

// Selects application.  Returns 1 if success, 0 otherwise
int select_applet(uint8_t * aid, int len)
{
    if (applet_cmp(aid, len, (uint8_t *)AID_FIDO, sizeof(AID_FIDO) - 1) == 0)
    {
        NFC_STATE.selected_applet = APP_FIDO;
        return APP_FIDO;
    }
    else if (applet_cmp(aid, len, (uint8_t *)AID_NDEF_TYPE_4, sizeof(AID_NDEF_TYPE_4) - 1) == 0)
    {
        NFC_STATE.selected_applet = APP_NDEF_TYPE_4;
        return APP_NDEF_TYPE_4;
    }
    else if (applet_cmp(aid, len, (uint8_t *)AID_CAPABILITY_CONTAINER, sizeof(AID_CAPABILITY_CONTAINER) - 1) == 0)
    {
        NFC_STATE.selected_applet = APP_CAPABILITY_CONTAINER;
        return APP_CAPABILITY_CONTAINER;
    }
    else if (applet_cmp(aid, len, (uint8_t *)AID_NDEF_TAG, sizeof(AID_NDEF_TAG) - 1) == 0)
    {
        NFC_STATE.selected_applet = APP_NDEF_TAG;
        return APP_NDEF_TAG;
    }
    return APP_NOTHING;
}

void apdu_process(uint8_t buf0, uint8_t *apduptr, APDU_STRUCT *apdu)
{
    int selected;
    CTAP_RESPONSE ctap_resp;
    int status;
    uint16_t reslen;

    // check CLA
    if (apdu->cla != 0x00 && apdu->cla != 0x80) {
        printf1(TAG_NFC, "Unknown CLA %02x\r\n", apdu->cla);
        nfc_write_response(buf0, SW_CLA_INVALID);
        return;
    }
    
    // TODO this needs to be organized better
    switch(apdu->ins)
    {
        // ISO 7816. 7.1 GET RESPONSE command
        case APDU_GET_RESPONSE:
            if (apdu->p1 != 0x00 || apdu->p2 != 0x00)
            {
                nfc_write_response(buf0, SW_INCORRECT_P1P2);
                printf1(TAG_NFC, "P1 or P2 error\r\n");
                return;
            }
            
            // too many bytes needs. 0x00 and 0x100 - any length
            if (apdu->le != 0 && apdu->le != 0x100 && apdu->le > chain_buffer_len)
            {
                uint16_t wlresp = SW_WRONG_LENGTH;  // here can be 6700, 6C00, 6FXX. but the most standard way - 67XX or 6700
                if (chain_buffer_len <= 0xff)
                    wlresp += chain_buffer_len & 0xff;
                nfc_write_response(buf0, wlresp);
                printf1(TAG_NFC, "buffer length less than requesteds\r\n");
                return;
            }
            
            // create temporary packet
            uint8_t pck[255] = {0};
            size_t pcklen = 253;
            if (apdu->le)
                pcklen = apdu->le;
            if (pcklen > chain_buffer_len)
                pcklen = chain_buffer_len;

            printf1(TAG_NFC, "GET RESPONSE. pck len: %d buffer len: %d\r\n", pcklen, chain_buffer_len); 
            
            // create packet and add 61XX there if we have another portion(s) of data
            memmove(pck, chain_buffer, pcklen);
            size_t dlen = 0;
            if (chain_buffer_len - pcklen)
            {
                append_get_response(&pck[pcklen], chain_buffer_len - pcklen);
                dlen = 2;
            }

            // send
            nfc_write_response_chaining_plain(buf0, pck, pcklen + dlen); // dlen for 61XX
            
            // shift the buffer
            chain_buffer_len -= pcklen;
            memmove(chain_buffer, &chain_buffer[pcklen], chain_buffer_len);
        break;
        
        case APDU_INS_SELECT:
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
                selected = select_applet(apdu->data, apdu->lc);
                if (selected == APP_FIDO)
                {
					nfc_write_response_ex(buf0, (uint8_t *)"U2F_V2", 6, SW_SUCCESS);
					printf1(TAG_NFC, "FIDO applet selected.\r\n");
               }
               else if (selected != APP_NOTHING)
               {
                   nfc_write_response(buf0, SW_SUCCESS);
                   printf1(TAG_NFC, "SELECTED %d\r\n", selected);
               }
                else
                {
					nfc_write_response(buf0, SW_FILE_NOT_FOUND);
                    printf1(TAG_NFC, "NOT selected "); dump_hex1(TAG_NFC, apdu->data, apdu->lc);
                }
            }
        break;

        case APDU_FIDO_U2F_VERSION:
			if (NFC_STATE.selected_applet != APP_FIDO) {
				nfc_write_response(buf0, SW_INS_INVALID);
				break;
			}

			printf1(TAG_NFC, "U2F GetVersion command.\r\n");

			u2f_request_nfc(apduptr, apdu->data, apdu->lc, &ctap_resp);
            nfc_write_response_chaining(buf0, ctap_resp.data, ctap_resp.length, apdu->extended_apdu);
        break;

        case APDU_FIDO_U2F_REGISTER:
			if (NFC_STATE.selected_applet != APP_FIDO) {
				nfc_write_response(buf0, SW_INS_INVALID);
				break;
			}

			printf1(TAG_NFC, "U2F Register command.\r\n");

			if (apdu->lc != 64)
			{
				printf1(TAG_NFC, "U2F Register request length error. len=%d.\r\n", apdu->lc);
				nfc_write_response(buf0, SW_WRONG_LENGTH);
				return;
			}

			timestamp();


			// WTX_on(WTX_TIME_DEFAULT);
            // SystemClock_Config_LF32();
            // delay(300);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
			u2f_request_nfc(apduptr, apdu->data, apdu->lc, &ctap_resp);
            if (device_is_nfc() == NFC_IS_ACTIVE)  device_set_clock_rate(DEVICE_LOW_POWER_IDLE);
			// if (!WTX_off())
			// 	return;

			printf1(TAG_NFC, "U2F resp len: %d\r\n", ctap_resp.length);
            printf1(TAG_NFC,"U2F Register P2 took %d\r\n", timestamp());
            nfc_write_response_chaining(buf0, ctap_resp.data, ctap_resp.length, apdu->extended_apdu);

            printf1(TAG_NFC,"U2F Register answered %d (took %d)\r\n", millis(), timestamp());
       break;

        case APDU_FIDO_U2F_AUTHENTICATE:
			if (NFC_STATE.selected_applet != APP_FIDO) {
				nfc_write_response(buf0, SW_INS_INVALID);
				break;
			}

			printf1(TAG_NFC, "U2F Authenticate command.\r\n");

			if (apdu->lc != 64 + 1 + apdu->data[64])
			{
				delay(5);
				printf1(TAG_NFC, "U2F Authenticate request length error. len=%d keyhlen=%d.\r\n", apdu->lc, apdu->data[64]);
				nfc_write_response(buf0, SW_WRONG_LENGTH);
				return;
			}

			timestamp();
			// WTX_on(WTX_TIME_DEFAULT);
			u2f_request_nfc(apduptr, apdu->data, apdu->lc, &ctap_resp);
			// if (!WTX_off())
			// 	return;

			printf1(TAG_NFC, "U2F resp len: %d\r\n", ctap_resp.length);
            printf1(TAG_NFC,"U2F Authenticate processing %d (took %d)\r\n", millis(), timestamp());
			nfc_write_response_chaining(buf0, ctap_resp.data, ctap_resp.length, apdu->extended_apdu);
            printf1(TAG_NFC,"U2F Authenticate answered %d (took %d)\r\n", millis(), timestamp);
        break;

        case APDU_FIDO_NFCCTAP_MSG:
			if (NFC_STATE.selected_applet != APP_FIDO) {
				nfc_write_response(buf0, SW_INS_INVALID);
				return;
			}

			printf1(TAG_NFC, "FIDO2 CTAP message. %d\r\n", timestamp());

			// WTX_on(WTX_TIME_DEFAULT);
            device_disable_up(true);
            ctap_response_init(&ctap_resp);
            status = ctap_request(apdu->data, apdu->lc, &ctap_resp);
            device_disable_up(false);
			// if (!WTX_off())
			// 	return;

			printf1(TAG_NFC, "CTAP resp: 0x%02x  len: %d\r\n", status, ctap_resp.length);

			if (status == CTAP1_ERR_SUCCESS)
			{
				memmove(&ctap_resp.data[1], &ctap_resp.data[0], ctap_resp.length);
				ctap_resp.length += 3;
			} else {
				ctap_resp.length = 3;
			}
			ctap_resp.data[0] = status;
			ctap_resp.data[ctap_resp.length - 2] = SW_SUCCESS >> 8;
			ctap_resp.data[ctap_resp.length - 1] = SW_SUCCESS & 0xff;

            printf1(TAG_NFC,"CTAP processing %d (took %d)\r\n", millis(), timestamp());
			nfc_write_response_chaining(buf0, ctap_resp.data, ctap_resp.length, apdu->extended_apdu);
            printf1(TAG_NFC,"CTAP answered %d (took %d)\r\n", millis(), timestamp());
        break;

        case APDU_INS_READ_BINARY:
            // response length
            reslen = apdu->le & 0xffff; 
            switch(NFC_STATE.selected_applet)
            {
                case APP_CAPABILITY_CONTAINER:
                    printf1(TAG_NFC,"APP_CAPABILITY_CONTAINER\r\n");
                    if (reslen == 0 || reslen > sizeof(NFC_CC))
                        reslen = sizeof(NFC_CC);
                    nfc_write_response_ex(buf0, (uint8_t *)&NFC_CC, reslen, SW_SUCCESS);
                    ams_wait_for_tx(10);
                break;
                case APP_NDEF_TAG:
                    printf1(TAG_NFC,"APP_NDEF_TAG\r\n");
                    if (reslen == 0 || reslen > sizeof(NDEF_SAMPLE) - 1)
                        reslen = sizeof(NDEF_SAMPLE) - 1;
                    nfc_write_response_ex(buf0, NDEF_SAMPLE, reslen, SW_SUCCESS);
                    ams_wait_for_tx(10);
                break;
                default:
                    nfc_write_response(buf0, SW_FILE_NOT_FOUND);
                    printf1(TAG_ERR, "No binary applet selected!\r\n");
                    return;
                break;
            }
        break;
        
        case  APDU_SOLO_RESET:
            if (apdu->lc == 4 && !memcmp(apdu->data, "\x12\x56\xab\xf0", 4)) {
                printf1(TAG_NFC, "Reset...\r\n");
                nfc_write_response(buf0, SW_SUCCESS);
                delay(20);
                device_reboot();
                while(1);
            } else {
                printf1(TAG_NFC, "Reset FAIL\r\n");
                nfc_write_response(buf0, SW_INS_INVALID);
            }
        break;
        
        default:
            printf1(TAG_NFC, "Unknown INS %02x\r\n", apdu->ins);
			nfc_write_response(buf0, SW_INS_INVALID);
        break;
    }
}

void nfc_process_iblock(uint8_t * buf, int len)
{
    uint8_t block_offset = p14443_block_offset(buf[0]);
    
    // clear tx chain buffer if we have some other command than GET RESPONSE
    if (chain_buffer_tx && buf[block_offset + 1] != APDU_GET_RESPONSE) {
        chain_buffer_len = 0;
        chain_buffer_tx = false;
    }
    
    APDU_STRUCT apdu;
    uint16_t ret = apdu_decode(buf + block_offset, len - block_offset, &apdu);
    if (ret != 0) {
        printf1(TAG_NFC,"apdu decode error\r\n");
        nfc_write_response(buf[0], ret);
        return;
    }
    printf1(TAG_NFC,"apdu ok. %scase=%02x cla=%02x ins=%02x p1=%02x p2=%02x lc=%d le=%d\r\n", 
        apdu.extended_apdu ? "[e]":"", apdu.case_type, apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.lc, apdu.le);

    // APDU level chaining. ISO7816-4, 5.1.1. class byte
    if (!chain_buffer_tx && buf[block_offset] & 0x10) {
        
        if (chain_buffer_len + len > sizeof(chain_buffer)) {
            nfc_write_response(buf[0], SW_WRONG_LENGTH);
            return;
        }
        
        memmove(&chain_buffer[chain_buffer_len], apdu.data, apdu.lc);
        chain_buffer_len += apdu.lc;
        nfc_write_response(buf[0], SW_SUCCESS);
        printf1(TAG_NFC, "APDU chaining ok. %d/%d\r\n", apdu.lc, chain_buffer_len);
        return;
    }
    
    // if we have ISO 7816 APDU chain - move there all the data
    if (!chain_buffer_tx && chain_buffer_len > 0) {
        memmove(&apdu.data[chain_buffer_len], apdu.data, apdu.lc);
        memmove(apdu.data, chain_buffer, chain_buffer_len);
        apdu.lc += chain_buffer_len; // here apdu struct does not match with memory!
        printf1(TAG_NFC, "APDU chaining merge. %d/%d\r\n", chain_buffer_len, apdu.lc);
    }

    
    apdu_process(buf[0], &buf[block_offset], &apdu);
    
    printf1(TAG_NFC,"prev.Iblock: ");
	dump_hex1(TAG_NFC, buf, len);
}

static uint8_t ibuf[1024];
static int ibuflen = 0;

void clear_ibuf(void)
{
	ibuflen = 0;
	memset(ibuf, 0, sizeof(ibuf));
}

void nfc_process_block(uint8_t * buf, unsigned int len)
{
    printf1(TAG_NFC, "-----\r\n");
	if (!len)
		return;

    if (IS_PPSS_CMD(buf[0]))
    {
        printf1(TAG_NFC, "NFC_CMD_PPSS [%d] 0x%02x\r\n", len, (len > 2) ? buf[2] : 0);
        
        if (buf[1] == 0x11 && (buf[2] & 0x0f) == 0x00) {
            nfc_write_frame(buf, 1); // ack with correct start byte
        } else {
            printf1(TAG_NFC, "NFC_CMD_PPSS ERROR!!!\r\n");
            nfc_write_frame((uint8_t*)"\x00", 1); // this should not happend. but iso14443-4 dont have NACK here, so just 0x00
        }        
    }
    else if (IS_IBLOCK(buf[0]))
    {
        uint8_t block_offset = p14443_block_offset(buf[0]);
        if (p14443_have_cid(buf[0])) 
            current_cid = buf[1];
		if (buf[0] & 0x10)
		{
			printf1(TAG_NFC_APDU, "NFC_CMD_IBLOCK chaining blen=%d len=%d offs=%d\r\n", ibuflen, len, block_offset);
			if (ibuflen + len > sizeof(ibuf))
			{
				printf1(TAG_NFC, "I block memory error! must have %d but have only %d\r\n", ibuflen + len, sizeof(ibuf));
				nfc_write_response(buf[0], SW_INTERNAL_EXCEPTION);
				return;
			}

			printf1(TAG_NFC_APDU,"i> ");
			dump_hex1(TAG_NFC_APDU, buf, len);

			if (len > block_offset)
			{
				memcpy(&ibuf[ibuflen], &buf[block_offset], len - block_offset);
				ibuflen += len - block_offset;
			}

			// send R block
            rblock_acknowledge(buf[0], true);
		} else {
			if (ibuflen)
			{
				if (len > block_offset)
				{
					memcpy(&ibuf[ibuflen], &buf[block_offset], len - block_offset);
					ibuflen += len - block_offset;
				}

                // add last chaining to top of the block
				memmove(&ibuf[block_offset], ibuf, ibuflen);
				memmove(ibuf, buf, block_offset);
				ibuflen += block_offset;

				printf1(TAG_NFC_APDU, "NFC_CMD_IBLOCK chaining last block. blen=%d len=%d offset=%d\r\n", ibuflen, len, block_offset);

				printf1(TAG_NFC_APDU,"i> ");
				dump_hex1(TAG_NFC_APDU, buf, len);

				nfc_process_iblock(ibuf, ibuflen);
			} else {
                memcpy(ibuf, buf, len); // because buf only 32b
				nfc_process_iblock(ibuf, len);
			}
			clear_ibuf();
		}
    }
    else if (IS_RBLOCK(buf[0]))
    {
        if (p14443_have_cid(buf[0])) 
            current_cid = buf[1];
        rblock_acknowledge(buf[0], true);
        printf1(TAG_NFC, "NFC_CMD_RBLOCK\r\n");
    }
    else if (IS_SBLOCK(buf[0]))
    {

        if ((buf[0] & NFC_SBLOCK_DESELECT) == 0)
        {
            printf1(TAG_NFC, "NFC_CMD_SBLOCK, DESELECTED\r\n");
            uint8_t block_offset = p14443_block_offset(buf[0]);
            if (p14443_have_cid(buf[0])) 
                current_cid = buf[1];
            nfc_write_frame(buf, block_offset);
            ams_wait_for_tx(2);
            ams_write_command(AMS_CMD_SLEEP);
            nfc_state_init();
			clear_ibuf();
			WTX_clear();
        }
        else
        {
            printf1(TAG_NFC, "NFC_CMD_SBLOCK, Unknown. len[%d]\r\n", len);
            nfc_write_response(buf[0], SW_COND_USE_NOT_SATISFIED);
        }
        dump_hex1(TAG_NFC, buf, len);
    }
    else
    {
        printf1(TAG_NFC, "unknown NFC request\r\n len[%d]:", len);
        dump_hex1(TAG_NFC, buf, len);
    }
}

int nfc_loop(void)
{
    uint8_t buf[32];
    AMS_DEVICE ams;
    int len = 0;


    read_reg_block(&ams);
    uint8_t old_int0 = gl_int0;
    process_int0(ams.regs.int0);
    uint8_t state = AMS_STATE_MASK & ams.regs.rfid_status;

    if (state != AMS_STATE_SELECTED && state != AMS_STATE_SELECTEDX)
    {
        // delay(1);  // sleep ?
        return 0;
    }

    if (ams.regs.rfid_status)
    {
        // if (state != AMS_STATE_SENSE)
        //      printf1(TAG_NFC,"    %s  x%02x\r\n", ams_get_state_string(ams.regs.rfid_status), state);
    }
    if (ams.regs.int0 & AMS_INT_INIT || old_int0 & AMS_INT_INIT)
    {
        nfc_state_init();
    }
    if (ams.regs.int1)
    {
        // ams_print_int1(ams.regs.int1);
    }

    if (ams.regs.int0 & AMS_INT_RXE || old_int0 & AMS_INT_RXE)
    {
        if (ams.regs.buffer_status2)
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
                ams_write_command(AMS_CMD_SLEEP);
                printf1(TAG_NFC, "HLTA/Halt\r\n");
            break;
            case NFC_CMD_RATS:

                answer_rats(buf[1]);

                NFC_STATE.block_num = 1;
				clear_ibuf();
				WTX_clear();
            break;
            default:

                // ISO 14443-4
                nfc_process_block(buf,len);


            break;
        }

    }

    return len;

}
