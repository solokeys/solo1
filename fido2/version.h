#ifndef _VERSION_H_
#define _VERSION_H_


#ifndef SOLO_VERSION_MAJ

#define SOLO_VERSION_MAJ    0
#define SOLO_VERSION_MIN    0
#define SOLO_VERSION_PATCH    0

#endif

#define __STR_HELPER(x) #x
#define __STR(x) __STR_HELPER(x)

#ifndef SOLO_VERSION
#define SOLO_VERSION     __STR(SOLO_VERSION_MAJ) "." __STR(SOLO_VERSION_MIN) "." __STR(SOLO_VERSION_PATCH)
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct {
  union{
    uint32_t raw;
    struct {
      uint8_t major;
      uint8_t minor;
      uint8_t patch;
      uint8_t reserved;
    };
  };
} version_t;

bool is_newer(const version_t* const newer, const version_t* const older);
extern const version_t firmware_version ;


#endif
