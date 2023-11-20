#pragma once

#ifdef __cplusplus
extern "C" {
#endif
//------------------------------------------------------------------------------
//
// Types
//
//------------------------------------------------------------------------------
/// `BofObjectHandle` is an opaque handle to the object file (COFF or ELF).
/// `bofObjectInitFromMemory()` returns a valid handle if it succeeds.
/// You can execute underlying object file as many times you want using `bofObjectRun*()` functions.
/// When you are done using object file you should call `bofObjectRelease()`.
typedef struct BofObjectHandle { unsigned int bits; } BofObjectHandle;

/// `BofContext` represents an execution context for a single BOF run.
/// Every successful call to `bofObjectRun*()` returns an unique `BofContext` object.
/// `BofContext` stores BOF's output, BOF's return value and provides synchronization operations
/// for async BOF runs.
/// You should call `bofContextRelease()` when you no longer need it.
typedef struct BofContext BofContext;

/// `BofArgs` represents a set of user-provided arguments that will be passed to a BOF.
typedef struct BofArgs BofArgs;

/// `BofCompletionCallback` is a callback function type for `bofObjectRunAsync*()` functions.
typedef void (*BofCompletionCallback)(BofContext* bof_context, void* user_context);
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
int
bofObjectRunAsyncProc(BofObjectHandle bof_handle,
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
bofContextGetReturnedValue(BofContext* context);

BofObjectHandle
bofContextGetObjectHandle(BofContext* context);

void
bofContextWait(BofContext* context);

const char*
bofContextGetOutput(BofContext* context,
                    int* out_output_len); // optional (can be NULL)
//------------------------------------------------------------------------------
//
// Args functions
//
//------------------------------------------------------------------------------
int
bofArgsInit(BofArgs** out_args);

void
bofArgsRelease(BofArgs* args);

/// Returns zero on success
/// Returns negative value when error occurs
int
bofArgsAdd(BofArgs* args, unsigned char* arg, int arg_len);

void
bofArgsBegin(BofArgs* args);

void
bofArgsEnd(BofArgs* args);

const char*
bofArgsGetBuffer(BofArgs* args);

int
bofArgsGetBufferSize(BofArgs* args);
//------------------------------------------------------------------------------
#ifdef __cplusplus
}
#endif
