/// bof-launcher 1.0.1 (Beta)
///
/// Basic usage:
///
/// ```
/// // Init the library
/// if (bofLauncherInit() < 0) {
///     // handle the error
/// }
///
/// // Load object file (COFF or ELF) and get a handle to it
/// BofObjectHandle bof_handle;
/// if (bofObjectInitFromMemory(obj_file_data, obj_file_data_size, &bof_handle) < 0) {
///     // handle the error
/// }
///
/// BofArgs* args0 = NULL;
/// if (bofArgsInit(&args0) < 0) {
///     // handle the error
/// }
/// bofArgsBegin(args0);
/// bofArgsAdd(args0, "my str", 6);
/// bofArgsEnd(args0);
///
/// // Run BOF with arguments `args0`
/// BofContext* context0 = NULL;
/// if (bofObjectRun(bof_handle,
///                  bofArgsGetBuffer(args0),
///                  bofArgsGetBufferSize(args0),
///                  &context0) < 0) {
///     // handle the error
/// }
///
/// const char* output0 = bofContextGetOutput(context0, NULL);
/// if (output0) {
///     // handle BOF output
/// }
/// bofArgsRelease(args0);
/// bofContextRelease(context0);
///
///
/// // Run the same BOF with different arguments (`args1`)
/// BofArgs* args1 = NULL;
/// if (bofArgsInit(&args1) < 0) {
///     // handle the error
/// }
/// bofArgsBegin(args1);
/// bofArgsAdd(args1, "my str 2", 8);
/// bofArgsEnd(args1);
///
/// BofContext* context1 = NULL;
/// if (bofObjectRun(bof_handle,
///                  bofArgsGetBuffer(args1),
///                  bofArgsGetBufferSize(args1),
///                  &context1) < 0) {
///     // handle the error
/// }
///
/// // Get output from the second BOF run
/// const char* output1 = bofContextGetOutput(context1, NULL);
/// if (output1) {
///     // handle BOF output
/// }
/// bofArgsRelease(args1);
/// bofContextRelease(context1);
///
///
/// // Cleanup
/// bofObjectRelease(bof_handle);
/// bofLauncherRelease();
/// ```
///
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

/// Sets a key which is used for memory masking. Max. length is 32 bytes.
/// This function copies input key to the internal storage.
int
bofMemoryMaskKey(const unsigned char* key, int key_len);

/// Enables/disables memory masking for a given Win32 API call. Currently,
/// following APIs are supported:
///
/// CreateRemoteThread
/// CreateThread
/// ResumeThread
/// GetThreadContext
/// SetThreadContext
/// CreateFileMappingA
/// MapViewOfFile
/// OpenProcess
/// OpenThread
/// ReadProcessMemory
/// WriteProcessMemory
/// UnmapViewOfFile
/// VirtualAlloc
/// VirtualAllocEx
/// VirtualFree
/// VirtualProtect
/// VirtualProtectEx
/// VirtualQuery
/// CloseHandle
/// DuplicateHandle
///
/// To enable/disable masking for all supported functions special name 'all' can be used:
///
/// bofMemoryMaskSysApiCall("all", 1); // enables masking for all supported functions
/// bofMemoryMaskSysApiCall("ResumeThread", 0); // disables masking for a particular API
///
/// Returns 0 on success.
/// Returns value less than zero on error (if not supported API name is passed or if
/// bofLauncherInit() hasn't been called).
///
/// If memory masking is enabled for a given system function all calls to it made from
/// any BOF will be redirected to a special wrapper function which masks memory before
/// the actual system API call and unmasks it right after the call.
///
/// For example, if memory masking for "VirtualAlloc" is enabled, all VirtualAlloc() calls made
/// from any BOF will go through below pseudo code:
///
/// zgateVirtualAlloc(...) {
///     maskMemory();
///     ret = VirtualAlloc(...);
///     unmaskMemory();
///     return ret;
/// }
int
bofMemoryMaskSysApiCall(const char* api_name, int masking_enabled);

/// Runs BOF. Returns BOF exit code ([0;255]) or error code (value less than zero).
int
bofRun(const unsigned char* file_data_ptr,
       int file_data_len); // in bytes
//------------------------------------------------------------------------------
//
// Object functions
//
//------------------------------------------------------------------------------
/// `bofObjectInitFromMemory()` takes raw object file data (COFF or ELF) and
/// prepares it for execution on a local machine.
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

void*
bofObjectGetProcAddress(BofObjectHandle bof_handle, const char* name);

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
