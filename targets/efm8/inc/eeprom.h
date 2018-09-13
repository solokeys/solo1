#ifndef EEPROM_H_
#define EEPROM_H_

#include "app.h"

void eeprom_init();

void eeprom_read(uint16_t addr, uint8_t * buf, uint8_t len);

void _eeprom_write(uint16_t addr, uint8_t * buf, uint8_t len, uint8_t flags);

extern char __erase_mem[3];

#define eeprom_write(a,b,l) 		_eeprom_write(a,b,l,0x1)
#define eeprom_erase(a) 			_eeprom_write(a,__erase_mem,1,0x3)

#define EEPROM_DATA_START 			0xF800

#endif /* EEPROM_H_ */
