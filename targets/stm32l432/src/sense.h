#ifndef _SENSE_H_
#define _SENSE_H_

#include <stdint.h>

extern int _run_sense_app;

void tsc_init();

int tsc_sensor_exists();

uint32_t tsc_read_button(uint32_t index);

#endif
