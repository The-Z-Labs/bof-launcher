#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BofHandle { unsigned int bits; } BofHandle;
typedef struct BofContext BofContext;

typedef void (*BofCompletionCallback)(BofHandle bof_handle, int run_result, void* user_context);

typedef struct BofArgData {
    char* original;
    char* buffer;
    int length;
    int size;
} BofArgData;

/// Returns zero on success
/// Returns negative value when error occurs
int bofInitLauncher(void);

void bofDeinitLauncher(void);

/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
int bofLoad(const char* bof_name_or_id,
            const unsigned char* file_data_ptr,
            int file_data_len,
            BofHandle* out_bof_handle); // required (can't be NULL)

void bofUnload(BofHandle bof_handle);

int bofIsLoaded(BofHandle bof_handle);

/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
int bofRun(BofHandle bof_handle, unsigned char* arg_data_ptr, int arg_data_len);

int bofRunAsync(BofHandle bof_handle,
                unsigned char* arg_data_ptr,
                int arg_data_len,
                BofCompletionCallback completion_cb, // optional (can be NULL)
                void* completion_cb_context, // optional (can be NULL)
                BofContext** out_context); // required (can't be NULL)

int bofContextIsRunning(BofContext* context);
void bofContextWait(BofContext* context);
void bofContextRelease(BofContext* context);

/// Returns zero on success
/// Returns negative value when error occurs
int bofPackArg(BofArgData* data, unsigned char* arg, int arg_len);

const char* bofGetOutput(BofHandle bof_handle,
                         int *out_output_len); // optional (can be NULL)

void bofClearOutput(BofHandle bof_handle);

#ifdef __cplusplus
}
#endif
