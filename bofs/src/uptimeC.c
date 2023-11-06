#define _GNU_SOURCE
#include <stdio.h>
#include <utmpx.h>
#include <time.h>
#include <paths.h>
#include "beacon.h"

unsigned char go(unsigned char* arg_data, int arg_len) {
    struct utmpx *ut;

    setutxent();

    while ((ut = getutxent()) != NULL) {
        /* Sequential scan to EOF */
        printf("%-8s ", ut->ut_user);
        printf("%-9.9s ",
                (ut->ut_type == EMPTY) ?
                "EMPTY" :
                (ut->ut_type == RUN_LVL) ?
                "RUN_LVL" :
                (ut->ut_type == BOOT_TIME) ?
                "BOOT_TIME" :
                (ut->ut_type == NEW_TIME) ?
                "NEW_TIME" :
                (ut->ut_type == OLD_TIME) ?
                "OLD_TIME" :
                (ut->ut_type == INIT_PROCESS) ? "INIT_PR" :
                (ut->ut_type == LOGIN_PROCESS) ? "LOGIN_PR" :
                (ut->ut_type == USER_PROCESS) ? "USER_PR" :
                (ut->ut_type == DEAD_PROCESS) ? "DEAD_PR" : "???");
        printf("%5ld %-6.6s %-3.5s %-9.9s ", (long) ut->ut_pid,
                ut->ut_line, ut->ut_id, ut->ut_host);
        printf("%s", ctime((time_t *) &(ut->ut_tv.tv_sec)));
    }

    endutxent();
    return 0;
}
