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


#endif
