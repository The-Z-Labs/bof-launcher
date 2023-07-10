#include "bof.h"

#define NULL 0

int ctestBasic0(void) {
    if (bofInitLauncher() < 0) return 0;
    bofDeinitLauncher();
    return 1;
}

int ctestBasic1(const unsigned char* file_data, int file_size) {
    BofHandle bof_handle;
    if (bofLoad("ctestBasic1", file_data, file_size, &bof_handle) < 0) return 0;
    if (bofIsLoaded(bof_handle) != 1) return 0;

    int output_len;
    const char* output = bofGetOutput(bof_handle, &output_len);
    if (output != NULL) return 0;
    if (output_len != 0) return 0;

    output = bofGetOutput(bof_handle, NULL);
    if (output != 0) return 0;

    bofClearOutput(bof_handle);
    output = bofGetOutput(bof_handle, NULL);
    if (output != 0) return 0;

    bofUnload(bof_handle);
    if (bofIsLoaded(bof_handle) != 0) return 0;

    bofUnload(bof_handle);
    bofUnload(bof_handle);
    if (bofIsLoaded(bof_handle) != 0) return 0;

    return 1;
}

int ctestBasic2(const unsigned char* file_data, int file_size) {
    BofHandle bof_handle;
    if (bofLoad("ctestBasic2", file_data, file_size, &bof_handle) < 0) return 0;

    if (bofRun(bof_handle, NULL, 0) < 0) return 0;

    int output_len;
    const char* output = bofGetOutput(bof_handle, &output_len);
    if (output == NULL) return 0;
    if (output_len == 0) return 0;

    return 1;
}
