#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#define PAGE_SIZE		2048
#define PAGES			128

// Pages 119-127 are data
// Location of counter page and it's backup page
// The flash is wear leveled and counter should be fault tolerant
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)

// State of FIDO2 application
#define	STATE2_PAGE		(PAGES - 2)
#define	STATE1_PAGE		(PAGES - 1)

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)

// Start of application code
#define APPLICATION_START_PAGE	(16)
#define APPLICATION_START_ADDR	flash_addr(APPLICATION_START_PAGE)

// End of application code.  Leave some extra room for future data storage.
#define APPLICATION_END_PAGE	((PAGES - 19))					         // 119 is NOT included in application
#define APPLICATION_END_ADDR	(flash_addr(APPLICATION_END_PAGE)-8)     // NOT included in application

// Bootloader state.
#define AUTH_WORD_ADDR          (flash_addr(APPLICATION_END_PAGE)-8)

#endif
