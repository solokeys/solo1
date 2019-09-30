#ifndef _SENSE_H_
#define _SENSE_H_

#include <stdint.h>

void tsc_init(void);

int tsc_sensor_exists(void);

// Read button0 or button1
// Returns 1 if pressed, 0 if not.
uint32_t tsc_read_button(uint32_t index);

#endif
