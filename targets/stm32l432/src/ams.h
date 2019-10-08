// AS3956 interface
// https://ams.com/as3956
// https://ams.com/documents/20143/36005/AS3956_DS000546_7-00.pdf

#ifndef _AMS_H_
#define _AMS_H_

#include <stdint.h>
#include <stdbool.h>
#include "stm32l4xx_ll_gpio.h"


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
} __attribute__((packed)) AMS_DEVICE;

#define SELECT() LL_GPIO_ResetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)
#define UNSELECT() LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)

int ams_init(void);
void ams_configure(void);

void ams_read_buffer(uint8_t * data, int len);
void ams_write_buffer(uint8_t * data, int len);

void ams_write_command(uint8_t cmd);

void read_reg_block(AMS_DEVICE * dev);

uint8_t ams_read_reg(uint8_t addr);

void ams_write_reg(uint8_t addr, uint8_t tx);

const char * ams_get_state_string(uint8_t regval);
int ams_state_is_valid(uint8_t regval);


#define AMS_REG_IO_CONF                 0x00
#define AMS_REG_IC_CONF0                0x01
#define AMS_REG_IC_CONF1                0x02
#define AMS_REG_IC_CONF2                0x03
    #define AMS_RFCFG_EN                0x80
    #define AMS_TUN_MOD                 0x40
#define AMS_REG_RFID_STATUS             0x04
    #define AMS_HF_PON                  0x80
    #define AMS_STATE_MASK              0x78
    #define AMS_STATE_INVALID           0x04
    #define AMS_STATE_OFF               (0 << 3)
    #define AMS_STATE_SENSE             (1 << 3)
    #define AMS_STATE_RESOLUTION        (3 << 3)
    #define AMS_STATE_RESOLUTION_L2     (2 << 3)
    #define AMS_STATE_SELECTED          (6 << 3)
    #define AMS_STATE_SECTOR2           (7 << 3)
    #define AMS_STATE_SECTORX_2         (0xf << 3)
    #define AMS_STATE_SELECTEDX         (0xe << 3)
    #define AMS_STATE_SENSEX_L2         (0xa << 3)
    #define AMS_STATE_SENSEX            (0xb << 3)
    #define AMS_STATE_SLEEP             (0x9 << 3)
// ... //
#define AMS_REG_MASK_INT0               0x08
    #define AMS_MASK0_PU                (1<<7)  // power up
    #define AMS_MASK0_WU_A              (1<<6)  // selected INT
    #define AMS_MASK0_SLP               (1<<5)
    #define AMS_MASK0_EEW_RF            (1<<4)
    #define AMS_MASK0_EER_RF            (1<<3)
    #define AMS_MASK0_RXE               (1<<2)
    #define AMS_MASK0_TXE               (1<<1)
    #define AMS_MASK0_XRF               (1<<0)
#define AMS_REG_MASK_INT1               0x09
#define AMS_REG_INT0                    0x0a
    #define AMS_INT_XRF                 (1<<0)
    #define AMS_INT_TXE                 (1<<1)
    #define AMS_INT_RXE                 (1<<2)
    #define AMS_INT_EER_RF              (1<<3)
    #define AMS_INT_EEW_RF              (1<<4)
    #define AMS_INT_SLP                 (1<<5)
    #define AMS_INT_WU_A                (1<<6)
    #define AMS_INT_INIT                (1<<7)
#define AMS_REG_INT1                    0x0b
    #define AMS_INT_ACC_ERR             (1<<0)
    #define AMS_INT_EEAC_ERR            (1<<1)
    #define AMS_INT_IO_EEWR             (1<<2)
    #define AMS_INT_BF_ERR              (1<<3)
    #define AMS_INT_CRC_ERR             (1<<4)
    #define AMS_INT_PAR_ERR             (1<<5)
    #define AMS_INT_FRM_ERR             (1<<6)
    #define AMS_INT_RXS                 (1<<7)
#define AMS_REG_BUF2                    0x0c
    #define AMS_BUF_LEN_MASK            0x1f
    #define AMS_BUF_INVALID             0x80
#define AMS_REG_BUF1                    0x0d
// ... //
#define AMS_REG_PRODUCT_TYPE            0x1c
#define AMS_REG_PRODUCT_SUBTYPE         0x1d
#define AMS_REG_VERSION_MAJOR           0x1e
#define AMS_REG_VERSION_MINOR           0x1f

#define AMS_CONFIG_UID_ADDR				0x00
#define AMS_CONFIG_BLOCK0_ADDR          0x7e
#define AMS_CONFIG_BLOCK1_ADDR          0x7f

#define AMS_CFG1_VOLTAGE_LEVEL_1V9      (0x00<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V0      (0x01<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V1      (0x02<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V2      (0x03<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V3      (0x04<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V4      (0x05<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V5      (0x06<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V6      (0x07<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V7      (0x08<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V8      (0x09<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_2V9      (0x0a<<2)
#define AMS_CFG1_VOLTAGE_LEVEL_3V0      (0x0b<<2)

#define AMS_CFG1_OUTPUT_RESISTANCE_ZZ   0x00
#define AMS_CFG1_OUTPUT_RESISTANCE_100  0x01
#define AMS_CFG1_OUTPUT_RESISTANCE_50   0x02
#define AMS_CFG1_OUTPUT_RESISTANCE_25   0x03

#define AMS_CFG2_RFCFG_EN               (1<<7)
#define AMS_CFG2_TUN_MOD                (1<<6)

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
