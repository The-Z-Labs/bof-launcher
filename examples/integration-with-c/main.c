#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bof_launcher_api.h"

int main(int argc, char *argv[]) {
    int ret_code = 0;
    FILE* file = NULL;
    long file_len = 0;
    const char* file_name = argv[1];
    unsigned char* file_data = NULL;
    BofObjectHandle bof_handle = {0};
    BofContext* bof_context = NULL;
    const char* bof_output = NULL;
    BofArgs* bof_args = NULL;

    if (argc < 2) {
        printf("Usage: %s <bof-filename>\n", argv[0]);
        return 0;
    }
    printf("<bof-filename>: %s\n", file_name);

    file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("File not found. Please run 'zig build' in the root of the project.\n");
        ret_code = 1;
        goto cleanup;
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    fseek(file, 0, SEEK_SET);

    printf("File size is: %ld\n", file_len);

    file_data = malloc(file_len);
    if (file_data == NULL) {
        ret_code = 1;
        goto cleanup;
    }

    if (fread(file_data, 1, file_len, file) != file_len) {
        printf("Failed to read the file.\n");
        ret_code = 1;
        goto cleanup;
    }

    if (bofObjectInitFromMemory(file_data, file_len, &bof_handle) != 0) {
        ret_code = 1;
        goto cleanup;
    }

    printf("Running BOF from command line C application...\n");

    if (bofArgsInit(&bof_args) != 0) {
        ret_code = 1;
        goto cleanup;
    }
    bofArgsBegin(bof_args);
    for (int i = 2; i < argc; ++i) {
        bofArgsAdd(bof_args, (unsigned char*)argv[i], strlen(argv[i]));
    }
    bofArgsEnd(bof_args);
 
    if (bofObjectRun(bof_handle,bofArgsGetBuffer(bof_args),
        bofArgsGetBufferSize(bof_args), &bof_context) != 0) {
        ret_code = 1;
        goto cleanup;
    }
    if (bof_context == NULL) {
        ret_code = 1;
        goto cleanup;
    }

    bof_output = bofContextGetOutput(bof_context, NULL);
    if (bof_output)
        printf("\n%s\n", bof_output);

cleanup:
    bofObjectRelease(bof_handle);
    if (bof_args) bofArgsRelease(bof_args);
    if (bof_context) bofContextRelease(bof_context);
    if (file_data) free(file_data);
    if (file) fclose(file);
    return ret_code;
}
