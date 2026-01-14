///name: whereami
///description: "Print hypervisor vendor signature from CPUID"
///author: Z-Labs
///tags: ['windows', 'linux','host-recon','z-labs']
///OS: cross
///sources:
///    - 'https://raw.githubusercontent.com/The-Z-Labs/bof-launcher/main/bofs/src/whereami.zig'
///examples: '
/// whereami
///'
///errors:
///- name: UnknownHypervisor
///  code: 0x1
///  message: "Unknown vendor signature"
///- name: UnknownError
///  code: 0x2
///  message: "Unknown error"
const std = @import("std");
const bofapi = @import("bof_api");
const beacon = bofapi.beacon;

// BOF-specific error codes
const BofErrors = enum(u8) {
    UnknownHypervisor = 0x1,
    UnknownError,
};

// https://github.com/systemd/systemd/blob/main/src/basic/virt.c

const Hypervisor = enum(u8) {
    Xen = 0x0,
    QEMUwithKVM,
    QEMU,
    VMWare,
    HyperV,
    bhyve,
    QNX,
    ACRN,
    SRE,
    AppleVZ
};

const hypervisor_sig = [_][]const u8 {
    "XenVMMXenVMM",
    "KVMKVMKVM",
    "Linux KVM Hv",
    "TCGTCGTCGTCG",
    "VMwareVMware",
    "Microsoft Hv",
    "bhyve bhyve ",
    "QNXQVMBSQG",
    "ACRNACRNACRN",
    "SRESRESRESRE",
    "Apple VZ",
};


// https://github.com/ziglang/zig/blob/738d2be9d6b6ef3ff3559130c05159ef53336224/lib/std/zig/system/x86.zig

const CpuidLeaf = packed struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf_id: u32, subid: u32) CpuidLeaf {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf_id),
          [_] "{ecx}" (subid),
    );

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

fn cpuidHypervisorType() error{
    UnknownHypervisor,
    UnknownError
}!Hypervisor {
    // https://lwn.net/Articles/301888/ 

    const Sig = extern union {
        sig32: [3]u32,
        text: [13]u8 
    };

    var sig: Sig = .{
        .text = [_]u8{0} ** 13
    };

    const leaf_0x4 = cpuid(0x40000000, 0);
    sig = Sig{
        .sig32 = .{ leaf_0x4.ebx, leaf_0x4.ecx, leaf_0x4.edx }
    };

    const cpuid_sig = std.mem.sliceTo(&sig.text, 0);

    for (hypervisor_sig, 0..) |hyper_sig, i| {

        if(std.mem.eql(u8, hyper_sig, cpuid_sig)) {
            return @as(Hypervisor, @enumFromInt(i));
        }
    }

    return error.UnknownHypervisor;
}

pub export fn go(adata: ?[*]u8, alen: i32) callconv(.c) u8 {
    @import("bof_api").init(adata, alen, .{});

    // let's detect if there is a hypervisor
    const leaf_0x1 = cpuid(0x1, 0); 
    const hypervisor_bit = leaf_0x1.ecx & 0x80000000;

    // a hypervisor is present, let's see which one
    if (hypervisor_bit != 0) {
        const hypervisor_type = cpuidHypervisorType() catch |err| switch (err) {
            error.UnknownHypervisor => return @intFromEnum(BofErrors.UnknownHypervisor),
            else => return @intFromEnum(BofErrors.UnknownError),
        };

        bofapi.print(.output, "CPUID Hypervisor: {s}", .{@tagName(hypervisor_type)});
    }

    return 0;
}
