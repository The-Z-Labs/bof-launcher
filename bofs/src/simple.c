#include <stdlib.h>
#include "beacon.h"

unsigned char go(unsigned char* arg_data, int arg_len) {
  char* buffer = malloc(123);
  buffer[0] = 'x';
  buffer[1] = 0;
  BeaconOutput(0, buffer, 10);
  free(buffer);
  return 0;
}
