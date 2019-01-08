#ifndef _NFC_H_
#define _NFC_H_

#include <stdint.h>

void nfc_loop();
void nfc_init();

typedef union
{
    uint8_t buf[0x20];
    struct {
        uint8_t io_conf;                // 0x00
        uint8_t ic_conf0;               // 0x01
        uint8_t ic_conf1;               // 0x02
        uint8_t ic_conf2;               // 0x03
        uint8_t rfid_status;            // 0x04
        uint8_t ic_status;              // 0x05
        uint8_t _nc0[2];                   // 0x06 - 0x07
        uint8_t mask_int0;              // 0x08
        uint8_t mask_int1;              // 0x09
        uint8_t int0;                   // 0x0a
        uint8_t int1;                   // 0x0b
        uint8_t buffer_status2;         // 0x0c
        uint8_t buffer_status1;         // 0x0d
        uint8_t last_nfc_addr;          // 0x0e
        uint8_t _nc1[0x1b - 0x0f + 1];  // 0x0f - 0x1b
        uint8_t product_type;           // 0x1c
        uint8_t product_subtype;        // 0x1d
        uint8_t version_maj;            // 0x1e
        uint8_t version_min;            // 0x1f
    } regs;
} AMS_DEVICE;

#define AMS_REG_IO_CONF                 0x00
#define AMS_REG_IC_CONF0                0x01
#define AMS_REG_IC_CONF1                0x02
#define AMS_REG_IC_CONF2                0x03

#define AMS_CMD_DEFAULT                 0x02
#define AMS_CMD_CLEAR_BUFFER            0x04
#define AMS_CMD_RESTART_TRANSCEIVER     0x06
#define AMS_CMD_DIS_EN_TRANSCEIVER      0x07
#define AMS_CMD_TRANSMIT_BUFFER         0x08
#define AMS_CMD_TRANSMIT_ACK            0x09
#define AMS_CMD_TRANSMIT_NACK0          0x0A
#define AMS_CMD_TRANSMIT_NACK1          0x0B
#define AMS_CMD_TRANSMIT_NACK4          0x0D
#define AMS_CMD_TRANSMIT_NACK5          0x0C
#define AMS_CMD_SLEEP                   0x10
#define AMS_CMD_SENSE                   0x11
#define AMS_CMD_SENSE_SLEEP             0x12

#endif
