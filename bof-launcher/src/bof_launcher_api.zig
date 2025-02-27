/// bof-launcher 1.0.0 (Beta)
///
/// Basic usage:
///
/// ```
/// const bof = @import("bof_launcher_api");
///
/// try bof.initLauncher();
/// defer bof.releaseLauncher();
///
/// // Load object file (COFF or ELF) and get a handle to it
/// const bof_handle = try bof.Object.initFromMemory(obj_file_data);
/// defer bof_handle.release();
///
/// const args0 = try bof.Args.init();
/// defer args0.release();
/// args0.begin();
/// try args0.add("my str");
/// args0.end();
///
/// // Run BOF with arguments `args0`
/// const context0 = try bof_handle.run(args0.getBuffer());
/// defer context0.release();
///
/// if (context0.getOutput()) |output| {
///     // handle BOF output
/// }
///
///
/// // Run the same BOF with different arguments (`args1`)
/// const args1 = try bof.Args.init();
/// defer args1.release();
/// args1.begin();
/// try args1.add("my str 2");
/// args1.end();
///
/// const context1 = try bof_handle.run(args1.getBuffer());
/// defer context1.release();
///
/// if (context1.getOutput()) |output| {
///     // handle BOF output
/// }
/// ```
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

pub const run = bofRun;
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
    /// it for execution on a local machine.
    /// It parses data, maps object file to memory, performs relocations, resolves external symbols, etc.
    pub fn initFromMemory(file_data: []const u8) Error!Object {
        var object: Object = undefined;
        if (bofObjectInitFromMemory(
            file_data.ptr,
            @intCast(file_data.len),
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

    pub fn getProcAddress(bof_handle: Object, name: [:0]const u8) ?*anyopaque {
        return bofObjectGetProcAddress(bof_handle, name);
    }

    /// `run()` executes loaded object file identified by `bof_handle` in a
    /// synchronous mode.
    /// `run()` will return when BOF finishes its execution.
    /// You can run underlying object file as many times as you want, each run will
    /// return unique `Context` object.
    ///
    /// Unique `Context` object is returned and
    /// must be released with `Context.release()` when no longer needed.
    ///
    /// `Context.getOutput()` - should be used to retrieve BOF's output.
    /// `Context.getExitCode()` - should be used to retrieve BOF's exit code.
    ///
    /// Example:
    /// ```
    /// const exec_ctx = try object.run(null);
    /// defer exec_ctx.release();
    ///
    /// if (exec_ctx.getOutput()) |output| {
    ///     std.debug.print("Exit code: {d}.\nOutput: {s}\n", exec_ctx.getExitCode(), output);
    /// }
    /// ```
    pub fn run(bof_handle: Object, arg_data: ?[]u8) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRun(
            bof_handle,
            if (arg_data) |d| d.ptr else null,
            if (arg_data) |d| @intCast(d.len) else 0,
            &context,
        ) < 0) return error.Unknown;
        return context;
    }

    /// `runAsyncThread()` executes loaded object file identified by
    /// `bof_handle` in an asynchronous mode.
    /// `runAsyncThread()` executes BOF in a dedicated thread - it launches
    /// BOF in a thread and returns immediately (does not block main thread).
    /// You can run underlying object file as many times as you want, each run will
    /// return unique `Context` object.
    ///
    /// Unique `Context` object is returned and
    /// must be released with `Context.release()` when no longer needed.
    ///
    /// `Context.isRunning()` - should be used to check if BOF has finished its
    ///                         execution.
    /// `Context.wait()` - should be used to wait for BOF to finish its execution.
    ///
    /// When BOF has finished its execution below functions can be used:
    /// `Context.getOutput()` - to retrieve BOF's output.
    /// `Context.getExitCode()` - to retrieve BOF's exit code.
    pub fn runAsyncThread(
        bof_handle: Object,
        arg_data: ?[]u8,
        completion_cb: ?CompletionCallback,
        completion_cb_context: ?*anyopaque,
    ) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRunAsyncThread(
            bof_handle,
            if (arg_data) |d| d.ptr else null,
            if (arg_data) |d| @intCast(d.len) else 0,
            completion_cb,
            completion_cb_context,
            &context,
        ) < 0) return error.Unknown;
        return context;
    }

    /// `runAsyncProcess()` executes loaded object file identified by
    /// `bof_handle` in an asynchronous mode.
    /// `runAsyncProcess()` executes BOF in a new dedicated process - it
    /// launches BOF in a cloned process and returns immediately
    /// (does not block main thread).
    /// You can run underlying object file as many times as you want, each run will
    /// return unique `Context` object.
    ///
    /// Unique `Context` object is returned and
    /// must be released with `Context.release()` when no longer needed.
    ///
    /// `Context.isRunning()` - should be used to check if BOF has finished its
    ///                         execution.
    /// `Context.wait()` - should be used to wait for BOF to finish its execution.
    ///
    /// When BOF has finished its execution below functions can be used:
    /// `Context.getOutput()` - to retrieve BOF's output.
    /// `Context.getExitCode()` - to retrieve BOF's exit code.
    pub fn runAsyncProcess(
        bof_handle: Object,
        arg_data: ?[]u8,
        completion_cb: ?CompletionCallback,
        completion_cb_context: ?*anyopaque,
    ) Error!*Context {
        var context: *Context = undefined;
        if (bofObjectRunAsyncProcess(
            bof_handle,
            if (arg_data) |d| d.ptr else null,
            if (arg_data) |d| @intCast(d.len) else 0,
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
    /// Internally `Context` object allocates some memory and other resources.
    /// User is responsible for releasing those resources by calling
    /// `Context.release()` when context is no longer needed. Keep in mind that
    /// BOF's output will no longer be available after you call this function.
    pub const release = bofContextRelease;

    /// `Context.isRunning` returns `true` when BOF still hasn't finished
    /// its execution.
    /// When this function returns `false` it means that BOF has completed and its
    /// output is ready.
    pub fn isRunning(context: *Context) bool {
        return bofContextIsRunning(context) != 0;
    }

    /// `Context.wait()` function blocks execution until BOF completes.
    pub const wait = bofContextWait;

    /// `Context.getExitCode()` returns BOF's exit code. `0xff` will be returned if
    /// BOF hasn't completed yet.
    pub const getExitCode = bofContextGetExitCode;

    /// `Context.getOutput()` returns BOF's output printed with `BeaconPrintf()`.
    /// `null` will be returned if BOF hasn't completed yet.
    pub fn getOutput(context: *Context) ?[]const u8 {
        var len: c_int = 0;
        const ptr = bofContextGetOutput(context, &len);
        if (ptr == null) return null;
        return ptr.?[0..@intCast(len)];
    }

    /// Helper function for checking which object file is associtated with a given
    /// `context`.
    pub fn getObject(context: *Context) Object {
        return .{ .handle = bofContextGetObjectHandle(context) };
    }
};
//------------------------------------------------------------------------------
//
// Args
//
//------------------------------------------------------------------------------
/// `Args` represents a set of user-provided arguments that can be passed to a BOF.
pub const Args = opaque {
    /// `Args.init()` creates `Args` object which is used to parse and store
    /// arguments that are intended to be consumed by a BOF.
    pub fn init() Error!*Args {
        var args: *Args = undefined;
        if (bofArgsInit(&args) < 0) return error.Unknown;
        return args;
    }

    pub const release = bofArgsRelease;

    pub const begin = bofArgsBegin;

    pub const end = bofArgsEnd;

    /// `Args.add()` adds an argument to a `Args` object. Has to be called
    /// between `Args.begin()` and `Args.end()` calls.
    pub fn add(args: *Args, arg: []const u8) Error!void {
        if (bofArgsAdd(args, arg.ptr, @intCast(arg.len)) < 0) return error.Unknown;
    }

    pub fn getBuffer(args: *Args) ?[]u8 {
        const size = bofArgsGetBufferSize(args);
        if (bofArgsGetBuffer(args)) |buffer| {
            return buffer[0..@intCast(size)];
        }
        return null;
    }
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

extern fn bofObjectGetProcAddress(bof_handle: Object, name: ?[*:0]const u8) callconv(.C) ?*anyopaque;

extern fn bofRun(
    file_data_ptr: [*]const u8,
    file_data_len: c_int,
) callconv(.C) c_int;

extern fn bofObjectRun(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofObjectRunAsyncThread(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofObjectRunAsyncProcess(
    bof_handle: Object,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    completion_cb: ?CompletionCallback,
    completion_cb_context: ?*anyopaque,
    out_context: **Context,
) callconv(.C) c_int;

pub extern fn bofDebugRun(
    go_func: *const fn (?[*]u8, i32) callconv(.C) u8,
    arg_data_ptr: ?[*]u8,
    arg_data_len: c_int,
    out_context: **Context,
) callconv(.C) c_int;

extern fn bofContextRelease(context: *Context) callconv(.C) void;
extern fn bofContextIsRunning(context: *Context) callconv(.C) c_int;
extern fn bofContextWait(context: *Context) callconv(.C) void;
extern fn bofContextGetExitCode(context: *Context) callconv(.C) u8;
extern fn bofContextGetObjectHandle(context: *Context) callconv(.C) u32;
extern fn bofContextGetOutput(context: *Context, out_output_len: ?*c_int) callconv(.C) ?[*:0]const u8;

extern fn bofArgsInit(out_args: **Args) callconv(.C) c_int;
extern fn bofArgsRelease(args: *Args) callconv(.C) void;
extern fn bofArgsAdd(args: *Args, arg: [*]const u8, arg_len: c_int) callconv(.C) c_int;
extern fn bofArgsBegin(args: *Args) callconv(.C) void;
extern fn bofArgsEnd(args: *Args) callconv(.C) void;
pub extern fn bofArgsGetBuffer(args: *Args) callconv(.C) ?[*]u8;
pub extern fn bofArgsGetBufferSize(args: *Args) callconv(.C) c_int;
//------------------------------------------------------------------------------
