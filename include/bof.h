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
/// You can execute underlying object file as many times as you want using
/// `bofObjectRun*()` functions. When you are done using object file you should
/// call `bofObjectRelease()`.
typedef struct BofObjectHandle { unsigned int bits; } BofObjectHandle;

/// `BofContext` represents an execution context for a single BOF run.
/// Every successful call to `bofObjectRun*()` returns an unique `BofContext`
/// object. `BofContext` stores BOF's output, BOF's exit code and provides
/// synchronization operations for async BOF runs.
/// You should call `bofContextRelease()` when you no longer need it.
typedef struct BofContext BofContext;

/// `BofArgs` represents a set of user-provided arguments that can be passed to
/// any BOF.
typedef struct BofArgs BofArgs;

/// `BofCompletionCallback` is a callback function type for
/// `bofObjectRunAsync*()` functions.
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

/// `bofLauncherRelease()` releases all the resources (it will release all
/// unreleased BOF objects but not contexts).
void
bofLauncherRelease(void);
//------------------------------------------------------------------------------
//
// Object functions
//
//------------------------------------------------------------------------------
/// `bofObjectInitFromMemory()` takes raw object file data (COFF or ELF) and
/// prepares it for the execution on a local machine.
/// It parses data, maps object file to memory, performs relocations, resolves
/// external symbols, etc.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectInitFromMemory(const unsigned char* file_data_ptr,
                        int file_data_len, // in bytes
                        BofObjectHandle* out_bof_handle); // required (can't be `NULL`)

/// `bofObjectRelease()` releases all the resources associtated with a BOF object.
/// After this call `bof_handle` becomes invalid.
void
bofObjectRelease(BofObjectHandle bof_handle);

/// Returns positive value when `bof_handle` is valid.
/// Returns zero if `bof_handle` is invalid (released or not returned from 
/// successful call to `bofObjectInitFromMemory()`).
int
bofObjectIsValid(BofObjectHandle bof_handle);

/// `bofObjectRun()` executes loaded object file identified by `bof_handle` in a
/// synchronous mode.
/// `bofObjectRun()` will return when BOF finishes its execution.
/// You can run underlying object file as many times as you want, each run will
/// return unique `BofContext` object.
///
/// Unique `BofContext` object is returned in `out_context` parameter and
/// must be released with `bofContextRelease()` when no longer needed.
///
/// `bofContextGetOutput()` - should be used to retrieve BOF's output.
/// `bofContextGetExitCode()` - should be used to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
///
/// Example:
/// ```
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
/// ```
int
bofObjectRun(BofObjectHandle bof_handle,
             unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
             int arg_data_len, // usually: bofArgsGetBufferSize()
             BofContext** out_context); // required (can't be `NULL`)

/// `bofObjectRunAsyncThread()` executes loaded object file identified by
/// `bof_handle` in an asynchronous mode.
/// `bofObjectRunAsyncThread()` executes BOF in a dedicated thread - it launches
/// BOF in a thread and returns immediately (does not block main thread).
/// You can run underlying object file as many times as you want, each run will
/// return unique `BofContext` object.
///
/// Unique `BofContext` object is returned in `out_context` parameter and
/// must be released with `bofContextRelease()` when no longer needed.
///
/// `bofContextIsRunning()` - should be used to check if BOF has finished its
///                           execution.
/// `bofContextWait()` - should be used to wait for BOF to finish its execution.
///
/// When BOF has finished its execution below functions can be used:
/// `bofContextGetOutput()` - to retrieve BOF's output.
/// `bofContextGetExitCode()` - to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectRunAsyncThread(BofObjectHandle bof_handle,
                        unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
                        int arg_data_len, // usually: bofArgsGetBufferSize()
                        BofCompletionCallback completion_cb, // optional (can be `NULL`)
                        void* completion_cb_context, // optional (can be `NULL`)
                        BofContext** out_context); // required (can't be `NULL`)

/// `bofObjectRunAsyncProcess()` executes loaded object file identified by
/// `bof_handle` in an asynchronous mode.
/// `bofObjectRunAsyncProcess()` executes BOF in a new dedicated process - it
/// launches BOF in a cloned process and returns immediately
/// (does not block main thread).
/// You can run underlying object file as many times as you want, each run will
/// return unique `BofContext` object.
///
/// Unique `BofContext` object is returned in `out_context` parameter and
/// must be released with `bofContextRelease()` when no longer needed.
///
/// `bofContextIsRunning()` - should be used to check if BOF has finished its
///                           execution.
/// `bofContextWait()` - should be used to wait for BOF to finish its execution.
///
/// When BOF has finished its execution below functions can be used:
/// `bofContextGetOutput()` - to retrieve BOF's output.
/// `bofContextGetExitCode()` - to retrieve BOF's exit code.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofObjectRunAsyncProcess(BofObjectHandle bof_handle,
                         unsigned char* arg_data_ptr, // usually: bofArgsGetBuffer()
                         int arg_data_len, // usually: bofArgsGetBufferSize()
                         BofCompletionCallback completion_cb, // optional (can be `NULL`)
                         void* completion_cb_context, // optional (can be `NULL`)
                         BofContext** out_context); // required (can't be `NULL`)
//------------------------------------------------------------------------------
//
// Context functions
//
//------------------------------------------------------------------------------
/// Internally `BofContext` object allocates some memory and other resources.
/// User is responsible for releasing those resources by calling
/// `bofContextRelease()` when context is no longer needed. Keep in mind that
/// BOF's output will no longer be available after you call this function.
void
bofContextRelease(BofContext* context);

/// `bofContextIsRunning` returns positive value when BOF still hasn't finished
/// its execution.
/// When this function returns zero it means that BOF has completed and its
/// output is ready.
int
bofContextIsRunning(BofContext* context);

/// `bofContextWait()` function blocks execution until BOF completes.
void
bofContextWait(BofContext* context);

/// `bofContextGetExitCode()` returns BOF's exit code. `0xff` will be returned if
/// BOF hasn't completed yet.
unsigned char
bofContextGetExitCode(BofContext* context);

/// `bofContextGetOutput()` returns BOF's output printed with `BeaconPrintf()`.
/// `NULL` will be returned if BOF hasn't completed yet.
/// Optionally it can also return number of bytes that the output buffer contains.
const char*
bofContextGetOutput(BofContext* context,
                    int* out_output_len); // optional (can be `NULL`)

/// Helper function for checking which object file is associtated with a given
/// `context`.
BofObjectHandle
bofContextGetObjectHandle(BofContext* context);
//------------------------------------------------------------------------------
//
// Args functions
//
//------------------------------------------------------------------------------
/// `bofArgsInit()` creates `BofArgs` object which is used to parse and store
/// arguments that are intended to be consumed by a BOF.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
int
bofArgsInit(BofArgs** out_args);

void
bofArgsRelease(BofArgs* args);

/// `bofArgsAdd()` adds an argument to a `BofArgs` object. Has to be called
/// between `bofArgsBegin()` and `bofArgsEnd()` calls.
///
/// `arg` is treated as a pointer to data and doesn't need to be `\0` terminated.
/// `arg_len` is data length in bytes.
///
/// Returns zero on success.
/// Returns negative value when error occurs.
///
/// Example:
/// ```
/// bofArgsBegin(args);
/// bofArgsAdd(args, "my str", 6); // data will be treated as a string
/// bofArgsAdd(args, "z:my str", 8); // same as above
/// bofArgsAdd(args, "str:my str", 10); // same as above
/// bofArgsAdd(args, "i:1234", 6); // data will be treated as an integer (u32)
/// bofArgsAdd(args, "int:1234", 8); // same as above
/// bofArgsAdd(args, "s:1234", 6); // data will be treated as an integer (u16)
/// bofArgsAdd(args, "short:1234", 10); // same as above
/// bofArgsEnd(args);
///
/// bofObjectRun(bof_handle,
///              bofArgsGetBuffer(args),
///              bofArgsGetBufferSize(args),
///              &context);
/// ```
int
bofArgsAdd(BofArgs* args, unsigned char* arg, int arg_len);

void
bofArgsBegin(BofArgs* args);

void
bofArgsEnd(BofArgs* args);

/// `bofArgsGetBuffer()` returns a pointer to a raw buffer that can be directly
/// passed to a BOF.
const char*
bofArgsGetBuffer(BofArgs* args);

/// `bofArgsGetBufferSize()` returns size in bytes of the internal data buffer
/// (can be passed directly to bofObjectRun*() functions).
int
bofArgsGetBufferSize(BofArgs* args);
//------------------------------------------------------------------------------
#ifdef __cplusplus
}
#endif
