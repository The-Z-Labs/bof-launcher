#define _GNU_SOURCE
#include <stdio.h>
#include <utmpx.h>
#include <time.h>
#include <paths.h>
#include <unistd.h>
#include "beacon.h"

unsigned char go(unsigned char* arg_data, int arg_len) {
    struct utmpx *ut;
    struct utmpx ut_search;

    unsigned char name[64 + 1];
    size_t namelen = 64;

    gethostname(name, namelen);
    printf("hostanme: %s", name);

    ut_search.ut_type = BOOT_TIME;

    setutxent();
    ut = getutxid(&ut_search);

    printf("SEC: %s", ctime((time_t *) &(ut->ut_tv.tv_sec)));

    endutxent();
    return 0;
}
