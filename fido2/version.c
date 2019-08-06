#include "version.h"


static const version_t firmware_version __attribute__ ((section (".flag"))) __attribute__ ((__used__)) =  {
  .major = SOLO_VERSION_MAJ,
  .minor = SOLO_VERSION_MIN,
  .patch = SOLO_VERSION_PATCH,
  .reserved = 0
};

// from tinycbor, for a quick static_assert
#include <compilersupport_p.h>
cbor_static_assert(sizeof(version_t) == 4);
