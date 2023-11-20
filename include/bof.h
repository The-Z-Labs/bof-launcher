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
/// `bofLauncherInit()` needs to be called to initialize this library.
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofLauncherInit(void);

/// `bofLauncherRelease()` releases all the resources (it will release all unreleased BOF objects
/// but not contexts).
void
bofLauncherRelease(void);
//------------------------------------------------------------------------------
//
// Object functions
//
//------------------------------------------------------------------------------
/// `bofObjectInitFromMemory()` takes raw object file data (COFF or ELF) and prepares
/// it for the execution on a local machine.
/// It parses data, maps object file to memory, performs relocations, resolves external symbols, etc.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectInitFromMemory(const unsigned char* file_data_ptr,
                        int file_data_len, // in bytes
                        BofObjectHandle* out_bof_handle); // required (can't be NULL)

/// `bofObjectRelease()` releases all the resources associtated with a BOF object.
/// After this call `bof_handle` becomes invalid.
void
bofObjectRelease(BofObjectHandle bof_handle);

/// Returns positive value when `bof_handle` is valid.
/// Returns zero if `bof_handle` is invalid (released or not returned from successful call
/// to `bofObjectInitFromMemory()`).
int
bofObjectIsValid(BofObjectHandle bof_handle);

/// `bofObjectRun()` executes loaded object file identified by `bof_handle` in a synchronous mode.
/// `bofObjectRun()` will return when BOF finishes its execution.
///
/// Unique `BofContext` object is returned in `out_context` parameter and must be released
/// with `bofContextRelease()` when no longer needed.
///
/// `bofContextGetOutput()` - should be used to retrieve BOF output.
/// `bofContextGetExitCode()` - should be used to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
///
/// Example:
///
/// BofContext* exec_ctx = NULL;
/// if (bofObjectRun(bof_handle, NULL, 0, &exec_ctx) != 0) {
///     // handle error
/// }
/// if (exec_ctx) {
///     const char* output = bofContextGetOutput(exec_ctx, NULL);
///     printf("Exit code: %d.\nOutput: %s\n",
///            bofContextGetExitCode(exec_ctx), output ? output : "empty output");
///     bofContextRelease(exec_ctx);
///     exec_ctx = NULL;
/// }
int
bofObjectRun(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
             int arg_data_len, // usually: bofArgsGetBufferSize()
             BofContext** out_context); // required (can't be NULL)

/// `bofObjectRunAsyncThread()` executes loaded object file identified by `bof_handle` in an asynchronous mode.
/// `bofObjectRunAsyncThread()` executes BOF in a dedicated thread - it launches BOF in a thread and
/// returns immediately (does not block main thread).
///
/// Unique `BofContext` object is returned in `out_context` parameter and must be released
/// with `bofContextRelease()` when no longer needed.
///
/// `bofContextIsRunning()` - should be used to check if BOF has finished its execution.
/// `bofContextWait()` - should be used to wait for BOF to finish its execution.
///
/// When BOF has finished its execution below functions can be used:
/// `bofContextGetOutput()` - to retrieve BOF output.
/// `bofContextGetExitCode()` - to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectRunAsyncThread(BofObjectHandle bof_handle,
                        unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
                        int arg_data_len, // usually: bofArgsGetBufferSize()
                        BofCompletionCallback completion_cb, // optional (can be NULL)
                        void* completion_cb_context, // optional (can be NULL)
                        BofContext** out_context); // required (can't be NULL)

/// `bofObjectRunAsyncProcess()` executes loaded object file identified by `bof_handle` in an asynchronous mode.
/// `bofObjectRunAsyncProcess()` executes BOF in a new dedicated process - it launches BOF in a cloned process and
/// returns immediately (does not block main thread).
///
/// Unique `BofContext` object is returned in `out_context` parameter and must be released
/// with `bofContextRelease()` when no longer needed.
///
/// `bofContextIsRunning()` - should be used to check if BOF has finished its execution.
/// `bofContextWait()` - should be used to wait for BOF to finish its execution.
///
/// When BOF has finished its execution below functions can be used:
/// `bofContextGetOutput()` - to retrieve BOF output.
/// `bofContextGetExitCode()` - to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectRunAsyncProcess(BofObjectHandle bof_handle,
                         unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
                         int arg_data_len, // usually: bofArgsGetBufferSize()
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

BofObjectHandle
bofContextGetObjectHandle(BofContext* context);

void
bofContextWait(BofContext* context);

unsigned char
bofContextGetExitCode(BofContext* context);

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
