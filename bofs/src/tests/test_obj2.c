#include "beacon.h"

static int global_number = 0;
static int num_runs;

int test1(void) {
    return 1;
}

__attribute__((noinline))
int getNumShort(datap* parser) {
    return BeaconDataInt(parser);
}

int test2(void) {
    global_number += 5;
    return 3;
}

int test3(void) {
    return 5;
}

int getNumRuns(void) {
    return num_runs;
}

int getNumCalls(void) {
    static int num;
    return ++num;
}

unsigned char go(char* arg_data, int arg_len) {
    BeaconPrintf(0, "--- test_obj2.c ---\n%s\n", "bof");

    datap parser = {0};
    BeaconDataParse(&parser, arg_data, arg_len);
    int len = BeaconDataLength(&parser);
    const char* permissions = BeaconDataExtract(&parser, 0);
    const char* path = BeaconDataExtract(&parser, 0);
    int num = BeaconDataInt(&parser);
    int num_short = getNumShort(&parser);

    if (arg_len > 0) {
        BeaconPrintf(0, "arg_len (from go): %d\n", arg_len);
        BeaconPrintf(0, "Length: (from go): %d\n", len);
        BeaconPrintf(0, "permissions: (from go): %s\n", permissions);
        BeaconPrintf(0, "path: (from go): %s\n", path);
        BeaconPrintf(0, "number (int): (from go): %d\n", num);
        BeaconPrintf(0, "number (short): (from go): %d\n", num_short);
    }

    char** env = getEnviron();
    if (env && env[0]) {
        BeaconPrintf(0, "environ[0]: '%s'\n", env[0]);
    }
    BeaconPrintf(0, "OS name: '%s'\n", getOSName());

    global_number += 1;

    int res = 0;
    res += test1();
    res += test2();
    res += test3();

    res = res + global_number;
    global_number = 0;

    num_runs += 1;

    return (unsigned char)res;
}
