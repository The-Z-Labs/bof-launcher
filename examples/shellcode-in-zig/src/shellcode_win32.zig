const std = @import("std");
const PVOID = std.os.windows.PVOID;
const ULONG = std.os.windows.ULONG;
const USHORT = std.os.windows.USHORT;
const DWORD = std.os.windows.DWORD;
const UNICODE_STRING = std.os.windows.UNICODE_STRING;
const LIST_ENTRY = std.os.windows.LIST_ENTRY;

pub const hash_kernel32 = 0x7040ee75;
pub const hash_LoadLibraryA = 0x5fbff0fb;
pub const hash_ExitProcess = 0xb769339e;

pub const hash_user32 = 0x5a6bd3f3;
pub const hash_MessageBoxA = 0x384f14b4;

pub fn getDllBase(dll_hash: u32) usize {
    const peb = std.os.windows.peb();
    const head: *LIST_ENTRY = &peb.Ldr.InMemoryOrderModuleList;

    var current = head;

    while (true) {
        const table_entry: *LDR_DATA_TABLE_ENTRY = @ptrFromInt(
            @intFromPtr(current) - @offsetOf(LDR_DATA_TABLE_ENTRY, "InMemoryOrderLinks"),
        );

        if (table_entry.BaseDllName.Buffer != null) {
            const name: [*:0]u16 = @ptrCast(table_entry.BaseDllName.Buffer.?);
            if (djb2(u16, toLower(name)) == dll_hash) {
                return @intFromPtr(table_entry.DllBase);
            }
        }

        current = current.Flink;
        if (current == head)
            break;
    }
    return 0;
}

pub fn getProcAddress(dll_base: usize, proc_hash: u32) usize {
    const nt_headers_offset: u32 = @intCast(@as(*const IMAGE_DOS_HEADER, @ptrFromInt(dll_base)).e_lfanew);

    const nt_headers = @as(*const IMAGE_NT_HEADERS, @ptrFromInt(dll_base + nt_headers_offset)).*;

    const export_dir = @as(*const IMAGE_EXPORT_DIRECTORY, @ptrFromInt(dll_base +
        nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)).*;

    const address_table = @as([*]const u32, @ptrFromInt(dll_base + export_dir.AddressOfFunctions));
    const name_table = @as([*]const u32, @ptrFromInt(dll_base + export_dir.AddressOfNames));
    const ordinal_table = @as([*]const u16, @ptrFromInt(dll_base + export_dir.AddressOfNameOrdinals));

    var i: u32 = 0;
    while (i < export_dir.NumberOfNames) : (i += 1) {
        const name: [*:0]const u8 = @ptrFromInt(dll_base + name_table[i]);
        if (djb2(u8, name) == proc_hash) {
            const ordinal = ordinal_table[i];
            const rva = address_table[ordinal];
            return dll_base + rva;
        }
    }

    return 0;
}

fn toLower(str: [*:0]u16) [*:0]u16 {
    var i: u32 = 0;
    while (str[i] != 0) : (i += 1) {
        if (str[i] >= 'A' and str[i] <= 'Z') str[i] += 32;
    }
    return str;
}

fn djb2(comptime T: type, str: [*:0]const T) u32 {
    var hash: u32 = 5381;
    var i: u32 = 0;
    while (str[i] != 0) : (i += 1) {
        const c: u32 = @intCast(str[i]);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: ULONG,
    ObsoleteLoadCount: USHORT,
    TlsIndex: USHORT,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: ULONG,
};

const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [4]u16,
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [10]u16,
    e_lfanew: i32,
};

const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    BaseOfData: u32,
    ImageBase: u32,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u32,
    SizeOfStackCommit: u32,
    SizeOfHeapReserve: u32,
    SizeOfHeapCommit: u32,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS32 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 8) IMAGE_NT_HEADERS64 else IMAGE_NT_HEADERS32;

const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

comptime {
    std.debug.assert(@offsetOf(IMAGE_DOS_HEADER, "e_lfanew") == 60);
    std.debug.assert(@offsetOf(IMAGE_NT_HEADERS, "OptionalHeader") == 24);
    std.debug.assert(@offsetOf(IMAGE_EXPORT_DIRECTORY, "NumberOfFunctions") == 20);
}

const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
