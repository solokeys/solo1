#include "version.h"

//  FIXME test version check function
bool is_newer(const version_t* const newer, const version_t* const older){
  return (newer->major > older->major) ||
         (newer->major == older->major &&  newer->minor > older->minor) ||
         (newer->major == older->major &&  newer->minor == older->minor &&  newer->patch >= older->patch);
}
