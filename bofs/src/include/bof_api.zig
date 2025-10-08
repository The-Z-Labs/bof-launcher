pub const beacon = @import("beacon.zig");
pub const win32 = @import("bof_launcher_win32");
pub const posix = @import("posix.zig");
pub const asn1 = @import("asn1.zig");
pub const kerberos = @import("kerberos.zig");

const std = @import("std");

pub fn print(@"type": beacon.CallbackType, comptime fmt: []const u8, args: anytype) void {
    const len = std.fmt.count(fmt, args);
    if (len < 4096) {
        var buf: [4096]u8 = undefined;
        const str = std.fmt.bufPrintZ(buf[0..], fmt, args) catch unreachable;
        _ = beacon.printf.?(@"type", "%s", str.ptr);
    } else {
        const str = std.fmt.allocPrintZ(std.heap.page_allocator, fmt, args) catch unreachable;
        defer std.heap.page_allocator.free(str);
        _ = beacon.printf.?(@"type", "%s", str.ptr);
    }
}

//
// Functions that can be generated implicitly by the compiler
//
pub fn embedFunctionCode(name: []const u8) void {
    comptime {
        const want_windows_v2u64_abi = builtin.os.tag == .windows and builtin.cpu.arch == .x86_64;
        const want_aeabi = switch (builtin.abi) {
            .eabi,
            .eabihf,
            .musleabi,
            .musleabihf,
            .gnueabi,
            .gnueabihf,
            .android,
            .androideabi,
            => switch (builtin.cpu.arch) {
                .arm, .armeb, .thumb, .thumbeb => true,
                else => false,
            },
            else => false,
        };

        if (@import("builtin").mode != .Debug) {
            if (std.mem.eql(u8, name, "__stackprobe__")) {
                if (@import("builtin").os.tag == .windows) {
                    if (arch == .x86) {
                        xexport(&_chkstk, "_alloca");
                    } else if (arch == .x86_64) {
                        xexport(&___chkstk_ms, "___chkstk_ms");
                    }
                }
            } else if (std.mem.eql(u8, name, "memcpy")) {
                xexport(&memcpy, "memcpy");
            } else if (std.mem.eql(u8, name, "memset")) {
                xexport(&memset, "memset");
            } else if (std.mem.eql(u8, name, "__udivdi3")) {
                xexport(&__udivdi3, "__udivdi3");
            } else if (std.mem.eql(u8, name, "__divdi3")) {
                xexport(&__divdi3, "__divdi3");
            } else if (std.mem.eql(u8, name, "__modti3")) {
                if (want_windows_v2u64_abi) {
                    xexport(&__modti3_windows_x86_64, "__modti3");
                } else {
                    xexport(&__modti3, "__modti3");
                }
            } else if (std.mem.eql(u8, name, "__umoddi3")) {
                xexport(&__umoddi3, "__umoddi3");
            } else if (std.mem.eql(u8, name, "__divti3")) {
                if (want_windows_v2u64_abi) {
                    xexport(&__divti3_windows_x86_64, "__divti3");
                } else {
                    xexport(&__divti3, "__divti3");
                }
            } else if (std.mem.eql(u8, name, "__ashlti3")) {
                xexport(&__ashlti3, "__ashlti3");
            } else if (std.mem.eql(u8, name, "__ashldi3")) {
                xexport(&__ashldi3, "__ashldi3");
            } else if (std.mem.eql(u8, name, "__lshrdi3")) {
                xexport(&__lshrdi3, "__lshrdi3");
            } else if (std.mem.eql(u8, name, "__aeabi_llsr")) {
                if (want_aeabi) xexport(&__aeabi_llsr, "__aeabi_llsr");
            } else if (std.mem.eql(u8, name, "__aeabi_llsl")) {
                if (want_aeabi) xexport(&__aeabi_llsl, "__aeabi_llsl");
            } else if (std.mem.eql(u8, name, "__aeabi_uldivmod")) {
                if (want_aeabi) xexport(&__aeabi_uldivmod, "__aeabi_uldivmod");
            } else if (std.mem.eql(u8, name, "__aeabi_uidiv")) {
                if (want_aeabi) xexport(&__aeabi_uidiv, "__aeabi_uidiv");
            } else if (std.mem.eql(u8, name, "__aeabi_ldivmod")) {
                if (want_aeabi) xexport(&__aeabi_ldivmod, "__aeabi_ldivmod");
            } else if (std.mem.eql(u8, name, "__aeabi_uidivmod")) {
                if (want_aeabi) xexport(&__aeabi_uidivmod, "__aeabi_uidivmod");
            } else {
                unreachable;
            }
        }
    }
}

fn xexport(comptime ptr: *const anyopaque, name: []const u8) void {
    @export(ptr, .{ .name = name, .linkage = .strong });
}

fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = src.?[i];
    }

    return dest;
}

fn memset(dest: ?[*]u8, c: u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);

    for (0..len) |i| {
        dest.?[i] = c;
    }

    return dest;
}

fn __ashlti3(a: i128, b: i32) callconv(.C) i128 {
    return ashlXi3(i128, a, b);
}

fn __ashldi3(a: i64, b: i32) callconv(.C) i64 {
    return ashlXi3(i64, a, b);
}

fn __lshrdi3(a: i64, b: i32) callconv(.C) i64 {
    return lshrXi3(i64, a, b);
}

fn __aeabi_llsr(a: i64, b: i32) callconv(.AAPCS) i64 {
    return lshrXi3(i64, a, b);
}

fn __aeabi_llsl(a: i64, b: i32) callconv(.AAPCS) i64 {
    return ashlXi3(i64, a, b);
}

fn _chkstk() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.always_inline, win_probe_stack_adjust_sp, .{});
}

fn ___chkstk_ms() callconv(.Naked) void {
    @setRuntimeSafety(false);
    @call(.always_inline, win_probe_stack_only, .{});
}

fn __udivdi3(a: u64, b: u64) callconv(.C) u64 {
    return __udivmoddi4(a, b, null);
}

fn __udivmoddi4(a: u64, b: u64, maybe_rem: ?*u64) callconv(.C) u64 {
    return udivmod(u64, a, b, maybe_rem);
}

fn __divdi3(a: i64, b: i64) callconv(.C) i64 {
    // Set aside the sign of the quotient.
    const sign: u64 = @bitCast((a ^ b) >> 63);
    // Take absolute value of a and b via abs(x) = (x^(x >> 63)) - (x >> 63).
    const abs_a = (a ^ (a >> 63)) -% (a >> 63);
    const abs_b = (b ^ (b >> 63)) -% (b >> 63);
    // Unsigned division
    const res = __udivmoddi4(@bitCast(abs_a), @bitCast(abs_b), null);
    // Apply sign of quotient to result and return.
    return @bitCast((res ^ sign) -% sign);
}

fn __umoddi3(a: u64, b: u64) callconv(.C) u64 {
    var r: u64 = undefined;
    _ = __udivmoddi4(a, b, &r);
    return r;
}

fn __aeabi_uidiv(n: u32, d: u32) callconv(.AAPCS) u32 {
    return div_u32(n, d);
}

fn __modti3(a: i128, b: i128) callconv(.C) i128 {
    return mod(a, b);
}

const v2u64 = @Vector(2, u64);

fn __modti3_windows_x86_64(a: v2u64, b: v2u64) callconv(.C) v2u64 {
    return @bitCast(mod(@as(i128, @bitCast(a)), @as(i128, @bitCast(b))));
}

fn __divti3(a: i128, b: i128) callconv(.C) i128 {
    return div(a, b);
}

const v128 = @Vector(2, u64);

fn __divti3_windows_x86_64(a: v128, b: v128) callconv(.C) v128 {
    return @bitCast(div(@bitCast(a), @bitCast(b)));
}

fn __aeabi_uidivmod() callconv(.Naked) void {
    @setRuntimeSafety(false);
    // Divide r0 by r1; the quotient goes in r0, the remainder in r1
    asm volatile (
        \\ push {lr}
        \\ sub sp, #4
        \\ mov r2, sp
        \\ bl  %[__udivmodsi4]
        \\ ldr r1, [sp]
        \\ add sp, #4
        \\ pop {pc}
        :
        : [__udivmodsi4] "X" (&__udivmodsi4),
        : "memory"
    );
    unreachable;
}

fn __aeabi_uldivmod() callconv(.Naked) void {
    @setRuntimeSafety(false);
    // Divide r1:r0 by r3:r2; the quotient goes in r1:r0, the remainder in r3:r2
    asm volatile (
        \\ push {r4, lr}
        \\ sub sp, #16
        \\ add r4, sp, #8
        \\ str r4, [sp]
        \\ bl  %[__udivmoddi4]
        \\ ldr r2, [sp, #8]
        \\ ldr r3, [sp, #12]
        \\ add sp, #16
        \\ pop {r4, pc}
        :
        : [__udivmoddi4] "X" (&__udivmoddi4),
        : "memory"
    );
    unreachable;
}

fn __aeabi_idivmod() callconv(.Naked) void {
    @setRuntimeSafety(false);
    // Divide r0 by r1; the quotient goes in r0, the remainder in r1
    asm volatile (
        \\ push {lr}
        \\ sub sp, #4
        \\ mov r2, sp
        \\ bl  %[__divmodsi4]
        \\ ldr r1, [sp]
        \\ add sp, #4
        \\ pop {pc}
        :
        : [__divmodsi4] "X" (&__divmodsi4),
        : "memory"
    );
    unreachable;
}

fn __aeabi_ldivmod() callconv(.Naked) void {
    @setRuntimeSafety(false);
    // Divide r1:r0 by r3:r2; the quotient goes in r1:r0, the remainder in r3:r2
    asm volatile (
        \\ push {r4, lr}
        \\ sub sp, #16
        \\ add r4, sp, #8
        \\ str r4, [sp]
        \\ bl  %[__divmoddi4]
        \\ ldr r2, [sp, #8]
        \\ ldr r3, [sp, #12]
        \\ add sp, #16
        \\ pop {r4, pc}
        :
        : [__divmoddi4] "X" (&__divmoddi4),
        : "memory"
    );
    unreachable;
}

fn __udivmodsi4(a: u32, b: u32, rem: *u32) callconv(.C) u32 {
    const d = __udivsi3(a, b);
    rem.* = @bitCast(@as(i32, @bitCast(a)) -% (@as(i32, @bitCast(d)) * @as(i32, @bitCast(b))));
    return d;
}

fn __divmodsi4(a: i32, b: i32, rem: *i32) callconv(.C) i32 {
    const d = __divsi3(a, b);
    rem.* = a -% (d * b);
    return d;
}

fn __divmoddi4(a: i64, b: i64, rem: *i64) callconv(.C) i64 {
    const d = __divdi3(a, b);
    rem.* = a -% (d * b);
    return d;
}

fn __udivsi3(n: u32, d: u32) callconv(.C) u32 {
    return div_u32(n, d);
}

fn __divsi3(n: i32, d: i32) callconv(.C) i32 {
    return div_i32(n, d);
}

inline fn div_i32(n: i32, d: i32) i32 {
    // Set aside the sign of the quotient.
    const sign: u32 = @bitCast((n ^ d) >> 31);
    // Take absolute value of a and b via abs(x) = (x^(x >> 31)) - (x >> 31).
    const abs_n = (n ^ (n >> 31)) -% (n >> 31);
    const abs_d = (d ^ (d >> 31)) -% (d >> 31);
    // abs(a) / abs(b)
    const res = @as(u32, @bitCast(abs_n)) / @as(u32, @bitCast(abs_d));
    // Apply sign of quotient to result and return.
    return @bitCast((res ^ sign) -% sign);
}

inline fn div(a: i128, b: i128) i128 {
    const s_a = a >> (128 - 1);
    const s_b = b >> (128 - 1);

    const an = (a ^ s_a) -% s_a;
    const bn = (b ^ s_b) -% s_b;

    const r = udivmod(u128, @bitCast(an), @bitCast(bn), null);
    const s = s_a ^ s_b;
    return (@as(i128, @bitCast(r)) ^ s) -% s;
}

inline fn mod(a: i128, b: i128) i128 {
    const s_a = a >> (128 - 1); // s = a < 0 ? -1 : 0
    const s_b = b >> (128 - 1); // s = b < 0 ? -1 : 0

    const an = (a ^ s_a) -% s_a; // negate if s == -1
    const bn = (b ^ s_b) -% s_b; // negate if s == -1

    var r: u128 = undefined;
    _ = udivmod(u128, @as(u128, @bitCast(an)), @as(u128, @bitCast(bn)), &r);
    return (@as(i128, @bitCast(r)) ^ s_a) -% s_a; // negate if s == -1
}

inline fn div_u32(n: u32, d: u32) u32 {
    const n_uword_bits: c_uint = 32;
    // special cases
    if (d == 0) return 0; // ?!
    if (n == 0) return 0;
    var sr = @as(c_uint, @bitCast(@as(c_int, @clz(d)) - @as(c_int, @clz(n))));
    // 0 <= sr <= n_uword_bits - 1 or sr large
    if (sr > n_uword_bits - 1) {
        // d > r
        return 0;
    }
    if (sr == n_uword_bits - 1) {
        // d == 1
        return n;
    }
    sr += 1;
    // 1 <= sr <= n_uword_bits - 1
    // Not a special case
    var q: u32 = n << @intCast(n_uword_bits - sr);
    var r: u32 = n >> @intCast(sr);
    var carry: u32 = 0;
    while (sr > 0) : (sr -= 1) {
        // r:q = ((r:q)  << 1) | carry
        r = (r << 1) | (q >> @intCast(n_uword_bits - 1));
        q = (q << 1) | carry;
        // carry = 0;
        // if (r.all >= d.all)
        // {
        //      r.all -= d.all;
        //      carry = 1;
        // }
        const s = @as(i32, @bitCast(d -% r -% 1)) >> @intCast(n_uword_bits - 1);
        carry = @intCast(s & 1);
        r -= d & @as(u32, @bitCast(s));
    }
    q = (q << 1) | carry;
    return q;
}

// Arithmetic shift left: shift in 0 from right to left
// Precondition: 0 <= b < bits_in_dword
inline fn ashlXi3(comptime T: type, a: T, b: i32) T {
    const word_t = HalveInt(T, false);

    const input = word_t{ .all = a };
    var output: word_t = undefined;

    if (b >= word_t.bits) {
        output.s.low = 0;
        output.s.high = input.s.low << @intCast(b - word_t.bits);
    } else if (b == 0) {
        return a;
    } else {
        output.s.low = input.s.low << @intCast(b);
        output.s.high = input.s.high << @intCast(b);
        output.s.high |= input.s.low >> @intCast(word_t.bits - b);
    }

    return output.all;
}

// Logical shift right: shift in 0 from left to right
// Precondition: 0 <= b < T.bit_count
inline fn lshrXi3(comptime T: type, a: T, b: i32) T {
    const word_t = HalveInt(T, false);

    const input = word_t{ .all = a };
    var output: word_t = undefined;

    if (b >= word_t.bits) {
        output.s.high = 0;
        output.s.low = input.s.high >> @intCast(b - word_t.bits);
    } else if (b == 0) {
        return a;
    } else {
        output.s.high = input.s.high >> @intCast(b);
        output.s.low = input.s.high << @intCast(word_t.bits - b);
        output.s.low |= input.s.low >> @intCast(b);
    }

    return output.all;
}

const builtin = @import("builtin");
const arch = builtin.cpu.arch;
const native_endian = builtin.cpu.arch.endian();
const is_test = builtin.is_test;
const Log2Int = std.math.Log2Int;

fn HalveInt(comptime T: type, comptime signed_half: bool) type {
    return extern union {
        pub const bits = @divExact(@typeInfo(T).int.bits, 2);
        pub const HalfTU = std.meta.Int(.unsigned, bits);
        pub const HalfTS = std.meta.Int(.signed, bits);
        pub const HalfT = if (signed_half) HalfTS else HalfTU;

        all: T,
        s: if (native_endian == .little)
            extern struct { low: HalfT, high: HalfT }
        else
            extern struct { high: HalfT, low: HalfT },
    };
}

fn win_probe_stack_only() void {
    @setRuntimeSafety(false);

    switch (arch) {
        .thumb => {
            asm volatile (
                \\ lsl r4, r4, #2
                \\ mov r12, sp
                \\ push {r5, r6}
                \\ mov r5, r4
                \\1:
                \\ sub r12, r12, #4096
                \\ subs r5, r5, #4096
                \\ ldr r6, [r12]
                \\ bgt 1b
                \\ pop {r5, r6}
                \\ bx lr
            );
        },
        .aarch64 => {
            asm volatile (
                \\        lsl    x16, x15, #4
                \\        mov    x17, sp
                \\1:
                \\
                \\        sub    x17, x17, 4096
                \\        subs   x16, x16, 4096
                \\        ldr    xzr, [x17]
                \\        b.gt   1b
                \\
                \\        ret
            );
        },
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         push   %%rax
                \\         cmp    $0x1000,%%rax
                \\         lea    24(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         pop    %%rax
                \\         pop    %%rcx
                \\         ret
            );
        },
        .x86 => {
            asm volatile (
                \\         push   %%ecx
                \\         push   %%eax
                \\         cmp    $0x1000,%%eax
                \\         lea    12(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         pop    %%eax
                \\         pop    %%ecx
                \\         ret
            );
        },
        else => {},
    }

    unreachable;
}

fn win_probe_stack_adjust_sp() void {
    @setRuntimeSafety(false);

    switch (arch) {
        .x86_64 => {
            asm volatile (
                \\         push   %%rcx
                \\         cmp    $0x1000,%%rax
                \\         lea    16(%%rsp),%%rcx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\         sub    $0x1000,%%rax
                \\         cmp    $0x1000,%%rax
                \\         ja     2b
                \\ 1:
                \\         sub    %%rax,%%rcx
                \\         test   %%rcx,(%%rcx)
                \\
                \\         lea    8(%%rsp),%%rax
                \\         mov    %%rcx,%%rsp
                \\         mov    -8(%%rax),%%rcx
                \\         push   (%%rax)
                \\         sub    %%rsp,%%rax
                \\         ret
            );
        },
        .x86 => {
            asm volatile (
                \\         push   %%ecx
                \\         cmp    $0x1000,%%eax
                \\         lea    8(%%esp),%%ecx
                \\         jb     1f
                \\ 2:
                \\         sub    $0x1000,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\         sub    $0x1000,%%eax
                \\         cmp    $0x1000,%%eax
                \\         ja     2b
                \\ 1:
                \\         sub    %%eax,%%ecx
                \\         test   %%ecx,(%%ecx)
                \\
                \\         lea    4(%%esp),%%eax
                \\         mov    %%ecx,%%esp
                \\         mov    -4(%%eax),%%ecx
                \\         push   (%%eax)
                \\         sub    %%esp,%%eax
                \\         ret
            );
        },
        else => {},
    }

    unreachable;
}

const lo = switch (builtin.cpu.arch.endian()) {
    .big => 1,
    .little => 0,
};
const hi = 1 - lo;

// Returns a_ / b_ and sets maybe_rem = a_ % b.
fn udivmod(comptime T: type, a_: T, b_: T, maybe_rem: ?*T) T {
    @setRuntimeSafety(is_test);

    const HalfT = HalveInt(T, false).HalfT;
    const SignedT = std.meta.Int(.signed, @bitSizeOf(T));

    if (b_ > a_) {
        if (maybe_rem) |rem| {
            rem.* = a_;
        }
        return 0;
    }

    const a: [2]HalfT = @bitCast(a_);
    const b: [2]HalfT = @bitCast(b_);
    var q: [2]HalfT = undefined;
    var r: [2]HalfT = undefined;

    // When the divisor fits in 64 bits, we can use an optimized path
    if (b[hi] == 0) {
        r[hi] = 0;
        if (a[hi] < b[lo]) {
            // The result fits in 64 bits
            q[hi] = 0;
            q[lo] = divwide(HalfT, a[hi], a[lo], b[lo], &r[lo]);
        } else {
            // First, divide with the high part to get the remainder. After that a_hi < b_lo.
            q[hi] = a[hi] / b[lo];
            q[lo] = divwide(HalfT, a[hi] % b[lo], a[lo], b[lo], &r[lo]);
        }
        if (maybe_rem) |rem| {
            rem.* = @bitCast(r);
        }
        return @bitCast(q);
    }

    // 0 <= shift <= 63
    const shift: Log2Int(T) = @clz(b[hi]) - @clz(a[hi]);
    var af: T = @bitCast(a);
    var bf = @as(T, @bitCast(b)) << shift;
    q = @bitCast(@as(T, 0));

    for (0..shift + 1) |_| {
        q[lo] <<= 1;
        // Branchless version of:
        // if (af >= bf) {
        //     af -= bf;
        //     q[lo] |= 1;
        // }
        const s = @as(SignedT, @bitCast(bf -% af -% 1)) >> (@bitSizeOf(T) - 1);
        q[lo] |= @intCast(s & 1);
        af -= bf & @as(T, @bitCast(s));
        bf >>= 1;
    }
    if (maybe_rem) |rem| {
        rem.* = @bitCast(af);
    }
    return @bitCast(q);
}

fn divwide(comptime T: type, _u1: T, _u0: T, v: T, r: *T) T {
    @setRuntimeSafety(is_test);
    if (T == u64 and builtin.target.cpu.arch == .x86_64 and builtin.target.os.tag != .windows) {
        var rem: T = undefined;
        const quo = asm (
            \\divq %[v]
            : [_] "={rax}" (-> T),
              [_] "={rdx}" (rem),
            : [v] "r" (v),
              [_] "{rax}" (_u0),
              [_] "{rdx}" (_u1),
        );
        r.* = rem;
        return quo;
    } else {
        return divwide_generic(T, _u1, _u0, v, r);
    }
}

// Let _u1 and _u0 be the high and low limbs of U respectively.
// Returns U / v_ and sets r = U % v_.
fn divwide_generic(comptime T: type, _u1: T, _u0: T, v_: T, r: *T) T {
    const HalfT = HalveInt(T, false).HalfT;
    @setRuntimeSafety(is_test);
    var v = v_;

    const b = @as(T, 1) << (@bitSizeOf(T) / 2);
    var un64: T = undefined;
    var un10: T = undefined;

    const s: Log2Int(T) = @intCast(@clz(v));
    if (s > 0) {
        // Normalize divisor
        v <<= s;
        un64 = (_u1 << s) | (_u0 >> @intCast((@bitSizeOf(T) - @as(T, @intCast(s)))));
        un10 = _u0 << s;
    } else {
        // Avoid undefined behavior of (u0 >> @bitSizeOf(T))
        un64 = _u1;
        un10 = _u0;
    }

    // Break divisor up into two 32-bit digits
    const vn1 = v >> (@bitSizeOf(T) / 2);
    const vn0 = v & std.math.maxInt(HalfT);

    // Break right half of dividend into two digits
    const un1 = un10 >> (@bitSizeOf(T) / 2);
    const un0 = un10 & std.math.maxInt(HalfT);

    // Compute the first quotient digit, q1
    var q1 = un64 / vn1;
    var rhat = un64 -% q1 *% vn1;

    // q1 has at most error 2. No more than 2 iterations
    while (q1 >= b or q1 * vn0 > b * rhat + un1) {
        q1 -= 1;
        rhat += vn1;
        if (rhat >= b) break;
    }

    const un21 = un64 *% b +% un1 -% q1 *% v;

    // Compute the second quotient digit
    var q0 = un21 / vn1;
    rhat = un21 -% q0 *% vn1;

    // q0 has at most error 2. No more than 2 iterations.
    while (q0 >= b or q0 * vn0 > b * rhat + un0) {
        q0 -= 1;
        rhat += vn1;
        if (rhat >= b) break;
    }

    r.* = (un21 *% b +% un0 -% q0 *% v) >> s;
    return q1 *% b +% q0;
}

comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows) {
        _ = win32;
    }
}
