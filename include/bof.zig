//------------------------------------------------------------------------------
//
// Various types
//
//------------------------------------------------------------------------------
pub const Error = error{
    Unknown,
};

/// `CompletionCallback` is a callback function type for `Object.runAsync*()` functions.
pub const CompletionCallback = *const fn (
    bof_context: *Context,
    user_context: ?*anyopaque,
) callconv(.C) void;
//------------------------------------------------------------------------------
//
// Launcher functions
//
//------------------------------------------------------------------------------
/// `initLauncher()` needs to be called to initialize this library.
pub fn initLauncher() Error!void {
    if (bofLauncherInit() < 0) return error.Unknown;
}

/// `releaseLauncher()` releases all the resources (it will release all unreleased BOF objects
/// but not contexts).
pub const releaseLauncher = bofLauncherRelease;
//------------------------------------------------------------------------------
//
// Object
//
//------------------------------------------------------------------------------
/// `Object` is an opaque handle to the object file (COFF or ELF).
/// `Object.initFromMemory()` returns a valid handle if it succeeds.
/// You can execute underlying object file as many times you want using `Object.run*()` functions.
/// When you are done using object file you should call `Object.release()`.
pub const Object = extern struct {
    handle: u32,

    /// `initFromMemory()` takes raw object file data (COFF or ELF) and prepares
    /// it for the execution on a local machine.
    /// It parses data, maps object file to memory, performs relocations, resolves external symbols, etc.
    pub fn initFromMemory(
        file_data_ptr: [*]const u8,
        file_data_len: c_int,
    ) Error!Object {
        var object: Object = undefined;
        if (bofObjectInitFromMemory(
            file_data_ptr,
            file_data_len,
            &object,
        ) < 0) return error.Unknown;
        return object;
    }

    /// `release()` releases all the resources associtated with a BOF object.
    /// After this call `Object` becomes invalid.
    pub const release = bofObjectRelease;

    /// Returns `true` when this object is valid.
    /// Returns `false` when this object is invalid (released or not returned from successful call
    /// to `bofObjectInitFromMemory()`).
    pub fn isValid(bof_handle: Object) bool {
        return bofObjectIsValid(bof_handle) != 0;
    }

    pub fn run(
        bof_handle: Object,
        arg_data_ptr: ?[*]u8,
        arg_data_len: c_int,
    ) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRun(
            bof_handle,
            arg_data_ptr,
            arg_data_len,
            &context,
        ) < 0) return error.Unknown;
        return context;
    }

    pub fn runAsync(
        bof_handle: Object,
        arg_data_ptr: ?[*]u8,
        arg_data_len: c_int,
        completion_cb: ?CompletionCallback,
        completion_cb_context: ?*anyopaque,
    ) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRunAsync(
            bof_handle,
            arg_data_ptr,
            arg_data_len,
            completion_cb,
            completion_cb_context,
            &context,
        ) < 0) return error.Unknown;
        return context;
    }

    pub fn runAsyncProc(
        bof_handle: Object,
        arg_data_ptr: ?[*]u8,
        arg_data_len: c_int,
        completion_cb: ?CompletionCallback,
        completion_cb_context: ?*anyopaque,
    ) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRunAsyncProc(
            bof_handle,
            arg_data_ptr,
            arg_data_len,
            completion_cb,
            completion_cb_context,
            &context,
        ) < 0) return error.Unknown;
        return context;
    }
};
//------------------------------------------------------------------------------
//
// Context
//
//------------------------------------------------------------------------------
/// `Context` represents an execution context for a single BOF run.
/// Every successful call to `Object.run*()` returns an unique `Context` object.
/// `Context` stores BOF's output, BOF's return value and provides synchronization operations
/// for async BOF runs.
/// You should call `Context.release()` when you no longer need it.
pub const Context = opaque {
    pub const release = bofContextRelease;

    pub fn isRunning(context: *Context) bool {
        return bofContextIsRunning(context) != 0;
    }

    pub const wait = bofContextWait;

    pub const getReturnedValue = bofContextGetReturnedValue;

    pub const getObject = bofContextGetObjectHandle;

    pub fn getOutput(context: *Context) ?[]const u8 {
        var len: c_int = 0;
        const ptr = bofContextGetOutput(context, &len);
        if (ptr == null) return null;
        return ptr.?[0..@intCast(len)];
    }
};
//------------------------------------------------------------------------------
//
// Args
//
//------------------------------------------------------------------------------
/// `Args` represents a set of user-provided arguments that will be passed to a BOF.
pub const Args = opaque {
    pub fn init() Error!*Args {
        var args: *Args = undefined;
        if (bofArgsInit(&args) < 0) return error.Unknown;
        return args;
    }

    pub const release = bofArgsRelease;

    pub const begin = bofArgsBegin;

    pub const end = bofArgsEnd;

    /// Returns zero on success
    /// Returns negative value when error occurs
    pub fn add(args: *Args, arg: [*]const u8, arg_len: c_int) Error!void {
        if (bofArgsAdd(args, arg, arg_len) < 0) return error.Unknown;
    }

    pub const getBuffer = bofArgsGetBuffer;

    pub const getBufferSize = bofArgsGetBufferSize;
};
//------------------------------------------------------------------------------
//
// Raw C functions
//
//------------------------------------------------------------------------------
extern fn bofLauncherInit() callconv(.C) c_int;
extern fn bofLauncherRelease() callconv(.C) void;

extern fn bofObjectInitFromMemory(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
    out_bof_handle: *Object,
) callconv(.C) c_int;

extern fn bofObjectRelease(bof_handle: Object) callconv(.C) void;

extern fn bofObjectIsValid(bof_handle: Object) callconv(.C) c_int;

extern fn bofObjectRun(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofObjectRunAsync(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofObjectRunAsyncProc(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofContextRelease(context: *Context) callconv(.C) void;
extern fn bofContextIsRunning(context: *Context) callconv(.C) c_int;
extern fn bofContextWait(context: *Context) callconv(.C) void;
extern fn bofContextGetReturnedValue(context: *Context) callconv(.C) u8;
extern fn bofContextGetObjectHandle(context: *Context) callconv(.C) Object;
extern fn bofContextGetOutput(context: *Context, out_output_len: ?*c_int) callconv(.C) ?[*:0]const u8;

extern fn bofArgsInit(out_args: **Args) callconv(.C) c_int;
extern fn bofArgsRelease(args: *Args) callconv(.C) void;
extern fn bofArgsAdd(args: *Args, arg: [*]const u8, arg_len: c_int) callconv(.C) c_int;
extern fn bofArgsBegin(args: *Args) callconv(.C) void;
extern fn bofArgsEnd(args: *Args) callconv(.C) void;
extern fn bofArgsGetBuffer(args: *Args) callconv(.C) ?[*]u8;
extern fn bofArgsGetBufferSize(args: *Args) callconv(.C) c_int;
//------------------------------------------------------------------------------
