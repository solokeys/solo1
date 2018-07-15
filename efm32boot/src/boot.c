/**************************************************************************//**
 * @file boot.c
 * @brief Functions for booting another application
 * @author Silicon Labs
 * @version 1.03
 ******************************************************************************
 * @section License
 * <b>(C) Copyright 2014 Silicon Labs, http://www.silabs.com</b>
 *******************************************************************************
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * DISCLAIMER OF WARRANTY/LIMITATION OF REMEDIES: Silicon Labs has no
 * obligation to support this Software. Silicon Labs is providing the
 * Software "AS IS", with no express or implied warranties of any kind,
 * including, but not limited to, any implied warranties of merchantability
 * or fitness for any particular purpose or warranties against infringement
 * of any proprietary rights of a third party.
 *
 * Silicon Labs will not be liable for any consequential, incidental, or
 * special damages, or any other relief, or for any claim by any third party,
 * arising from your use of this Software.
 *
 ******************************************************************************/

#include "em_device.h"
#include "em_gpio.h"
#include "em_cmu.h"
#include "app.h"


/******************************************************************************
 * This function sets up the Cortex-M3 with a new SP and PC.
 *****************************************************************************/
#if defined ( __CC_ARM   )
__asm void BOOT_jump(uint32_t sp, uint32_t pc)
{
  /* Set new MSP, PSP based on SP (r0)*/
  msr msp, r0
  msr psp, r0

  /* Jump to PC (r1)*/
  bx r1
}
#else
void BOOT_jump(uint32_t sp, uint32_t pc)
{
  (void) sp;
  (void) pc;
  /* Set new MSP, PSP based on SP (r0)*/
  __asm("msr msp, r0");
  __asm("msr psp, r0");

  /* Jump to PC (r1)*/
  __asm("mov pc, r1");
}
#endif


/* Resets any peripherals that have been in use by
 * the bootloader before booting the appliation */
static void resetPeripherals(void)
{

}



/******************************************************************************
 * Boots the firmware. This function will activate the vector table
 * of the firmware application and set the PC and SP from this table.
 *****************************************************************************/
void BOOT_boot(void)
{
  uint32_t pc, sp;

  uint32_t *bootAddress = (uint32_t *)(JUMP_LOC);

  resetPeripherals();

  /* Set new vector table */
  SCB->VTOR = (uint32_t)bootAddress;

  /* Read new SP and PC from vector table */
  sp = bootAddress[0];
  pc = bootAddress[1];

  /* Do a jump by loading the PC and SP into the CPU registers */
  BOOT_jump(sp, pc);
}
