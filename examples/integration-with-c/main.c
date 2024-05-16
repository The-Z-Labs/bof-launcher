#include <stdio.h>
#include <stdlib.h>
#include "bof_launcher_api.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <bof-filename>\n", argv[0]);
        return 0;
    }
    const char* filename = argv[1];
    printf("<bof-filename>: %s\n", filename);

    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("File not found. Please run 'zig build' in the root of the project.\n");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("File size is: %ld\n", len);

    void* buf = malloc(len);
    if (buf == NULL) return 1;

    if (fread(buf, 1, len, fp) != len) {
        printf("Failed to read the file.\n");
        return 1;
    }

    BofObjectHandle bof_handle;
    if (bofObjectInitFromMemory((unsigned char*)buf, len, &bof_handle) < 0) return 1;

    printf("Running BOF from command line C application...\n");
 
    BofContext* bof_context = NULL;
    if (bofObjectRunAsyncThread(bof_handle, NULL, 0, NULL, NULL, &bof_context) < 0) return 1;
    if (bof_context == NULL) return 1;

    bofContextWait(bof_context);

    const char* output = bofContextGetOutput(bof_context, NULL);
    if (output)
        printf("\n%s\n", output);

    bofObjectRelease(bof_handle);
    bofContextRelease(bof_context);
    free(buf);
    fclose(fp);

    return 0;
}
