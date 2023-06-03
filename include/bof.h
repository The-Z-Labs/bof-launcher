#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BofHandle { unsigned int bits; } BofHandle;

typedef void (*BofCompletionCallback)(BofHandle bof_handle, int run_result, void* user_context);

typedef struct BofArgData {
    char* original;
    char* buffer;
    int length;
    int size;
} BofArgData;

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

/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
int bofLoadAndRun(const char* bof_name_or_id,
                  const unsigned char* file_data_ptr,
                  int file_data_len,
                  unsigned char* arg_data_ptr,
                  int arg_data_len,
                  BofHandle* out_bof_handle); // optional (can be NULL)

int bofRunAsync(BofHandle bof_handle,
                unsigned char* arg_data_ptr,
                int arg_data_len,
                BofCompletionCallback completion_cb,
                void* user_context);

/// Returns zero on success
/// Returns negative value when error occurs
int bofPackArg(BofArgData* data, unsigned char* arg, int arg_len);

const char* bofGetOutput(BofHandle bof_handle, int *out_output_len);

void bofClearOutput(BofHandle bof_handle);

/// Returns zero on success
/// Returns negative value when error occurs
int bofInitLauncher(void);

void bofDeinitLauncher(void);

#ifdef __cplusplus
}
#endif
