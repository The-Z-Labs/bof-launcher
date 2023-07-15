#pragma once
#ifdef __cplusplus
extern "C" {
#endif
//------------------------------------------------------------------------------
//
// Types
//
//------------------------------------------------------------------------------
typedef struct BofObjectHandle { unsigned int bits; } BofObjectHandle;
typedef struct BofContext BofContext;

typedef void (*BofCompletionCallback)(BofContext* bof_context, void* user_context);

typedef struct BofArgs {
    char* original;
    char* buffer;
    int length;
    int size;
} BofArgs;
//------------------------------------------------------------------------------
//
// Launcher functions
//
//------------------------------------------------------------------------------
/// Returns zero on success
/// Returns negative value when error occurs
int
bofLauncherInit(void);

void
bofLauncherRelease(void);
//------------------------------------------------------------------------------
//
// Object functions
//
//------------------------------------------------------------------------------
/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
int
bofObjectInitFromMemory(const unsigned char* file_data_ptr,
                        int file_data_len,
                        BofObjectHandle* out_bof_handle); // required (can't be NULL)
void
bofObjectRelease(BofObjectHandle bof_handle);

int
bofObjectIsValid(BofObjectHandle bof_handle);

/// Returns value returned from bof (zero or greater)
/// Returns negative value when error occurs
int
bofObjectRun(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr,
             int arg_data_len,
             BofContext** out_context); // required (can't be NULL)
int
bofObjectRunAsync(BofObjectHandle bof_handle,
                  unsigned char* arg_data_ptr,
                  int arg_data_len,
                  BofCompletionCallback completion_cb, // optional (can be NULL)
                  void* completion_cb_context, // optional (can be NULL)
                  BofContext** out_context); // required (can't be NULL)
//------------------------------------------------------------------------------
//
// Context functions
//
//------------------------------------------------------------------------------
void
bofContextRelease(BofContext* context);

int
bofContextIsRunning(BofContext* context);

unsigned char
bofContextGetResult(BofContext* context);

BofObjectHandle
bofContextGetObjectHandle(BofContext* context);

void
bofContextWait(BofContext* context);

const char*
bofContextGetOutput(BofContext* context,
                    int *out_output_len); // optional (can be NULL)
//------------------------------------------------------------------------------
//
// Args functions
//
//------------------------------------------------------------------------------
/// Returns zero on success
/// Returns negative value when error occurs
int
bofArgsAdd(BofArgs* args, unsigned char* arg, int arg_len);
//------------------------------------------------------------------------------
#ifdef __cplusplus
}
#endif
