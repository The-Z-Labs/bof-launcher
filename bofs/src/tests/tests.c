#include "bof_launcher_api.h"

#define NULL 0

int ctestBasic0(void) {
    if (bofLauncherInit() < 0) return 0;
    bofLauncherRelease();
    return 1;
}

int ctestBasic1(const unsigned char* file_data, int file_size) {
    BofObjectHandle bof_handle;
    if (bofObjectInitFromMemory(file_data, file_size, &bof_handle) < 0) return 0;
    if (bofObjectIsValid(bof_handle) != 1) return 0;

    bofObjectRelease(bof_handle);
    if (bofObjectIsValid(bof_handle) != 0) return 0;

    bofObjectRelease(bof_handle);
    bofObjectRelease(bof_handle);
    if (bofObjectIsValid(bof_handle) != 0) return 0;

    return 1;
}

int ctestBasic2(const unsigned char* file_data, int file_size) {
    BofObjectHandle bof_handle;
    if (bofObjectInitFromMemory(file_data, file_size, &bof_handle) < 0) return 0;

    BofContext* context = NULL;
    if (bofObjectRun(bof_handle, NULL, 0, &context) < 0) return 0;
    if (context == NULL) return 0;

    int output_len;
    const char* output = bofContextGetOutput(context, &output_len);
    if (output == NULL) return 0;
    if (output_len == 0) return 0;

    bofObjectRelease(bof_handle);
    bofContextRelease(context);

    if (bofObjectIsValid(bof_handle) != 0) return 0;

    return 1;
}
