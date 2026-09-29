const std = @import("std");
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;

pub const ATTACH_PARENT_PROCESS = 0xffff_ffff;

pub const ERROR_SUCCESS = 0;
pub const ERROR_INVALID_FUNCTION = 1;
pub const ERROR_INSUFFICIENT_BUFFER = 122;
pub const ERROR_MORE_DATA = 234;

pub const STATUS_SUCCESS = 0x00000000;
pub const STATUS_PROCESS_CLONED = 0x00000129;

pub const ACCESS_MASK = DWORD;
pub const OVERLAPPED = extern struct {
    Internal: ULONG_PTR,
    InternalHigh: ULONG_PTR,
    DUMMYUNIONNAME: extern union {
        DUMMYSTRUCTNAME: extern struct {
            Offset: DWORD,
            OffsetHigh: DWORD,
        },
        Pointer: ?PVOID,
    },
    hEvent: ?HANDLE,
};
pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: PVOID,
    AllocationBase: PVOID,
    AllocationProtect: DWORD,
    PartitionId: WORD,
    RegionSize: SIZE_T,
    State: DWORD,
    Protect: DWORD,
    Type: DWORD,
};
pub const SYSTEM_INFO = extern struct {
    anon1: extern union {
        dwOemId: DWORD,
        anon2: extern struct {
            wProcessorArchitecture: WORD,
            wReserved: WORD,
        },
    },
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: LPVOID,
    lpMaximumApplicationAddress: LPVOID,
    dwActiveProcessorMask: DWORD_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
};
pub const LIST_ENTRY = extern struct {
    Flink: *LIST_ENTRY,
    Blink: *LIST_ENTRY,
};

pub const RTL_CRITICAL_SECTION_DEBUG = extern struct {
    Type: WORD,
    CreatorBackTraceIndex: WORD,
    CriticalSection: *RTL_CRITICAL_SECTION,
    ProcessLocksList: LIST_ENTRY,
    EntryCount: DWORD,
    ContentionCount: DWORD,
    Flags: DWORD,
    CreatorBackTraceIndexHigh: WORD,
    SpareWORD: WORD,
};

pub const RTL_CRITICAL_SECTION = extern struct {
    DebugInfo: *RTL_CRITICAL_SECTION_DEBUG,
    LockCount: LONG,
    RecursionCount: LONG,
    OwningThread: HANDLE,
    LockSemaphore: HANDLE,
    SpinCount: ULONG_PTR,
};
pub const PRTL_CRITICAL_SECTION = *RTL_CRITICAL_SECTION;
pub const CRITICAL_SECTION = RTL_CRITICAL_SECTION;

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};
pub const BOOL = c_int;
pub const PBOOL = *BOOL;
pub const TRUE = 1;
pub const FALSE = 0;
pub const OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: ULONG,
    dwMajorVersion: ULONG,
    dwMinorVersion: ULONG,
    dwBuildNumber: ULONG,
    dwPlatformId: ULONG,
    szCSDVersion: [128]WCHAR,
};
pub const RTL_OSVERSIONINFOW = OSVERSIONINFOW;
pub const PSID = PVOID;
pub const NTSTATUS = u32;
pub const CLIENT_ID = extern struct {
    UniqueProcess: ?HANDLE,
    UniqueThread: ?HANDLE,
};
pub const ANSI_STRING = extern struct {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: ?[*]CHAR,
};
pub const PCANSI_STRING = *const ANSI_STRING;
pub const UNICODE_STRING = extern struct {
    Length: USHORT,
    MaximumLength: USHORT,
    Buffer: ?[*]WCHAR,
};
pub const PCUNICODE_STRING = *const UNICODE_STRING;
pub const INFINITE = 4294967295;
pub const BOOLEAN = BYTE;
pub const HRESULT = c_long;
pub const HLOCAL = HANDLE;

pub const FLOATING_SAVE_AREA = switch (native_arch) {
    .x86 => extern struct {
        ControlWord: DWORD,
        StatusWord: DWORD,
        TagWord: DWORD,
        ErrorOffset: DWORD,
        ErrorSelector: DWORD,
        DataOffset: DWORD,
        DataSelector: DWORD,
        RegisterArea: [80]BYTE,
        Cr0NpxState: DWORD,
    },
    else => @compileError("FLOATING_SAVE_AREA only defined on x86"),
};

pub const M128A = switch (native_arch) {
    .x86_64 => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    else => @compileError("M128A only defined on x86_64"),
};

pub const XMM_SAVE_AREA32 = switch (native_arch) {
    .x86_64 => extern struct {
        ControlWord: WORD,
        StatusWord: WORD,
        TagWord: BYTE,
        Reserved1: BYTE,
        ErrorOpcode: WORD,
        ErrorOffset: DWORD,
        ErrorSelector: WORD,
        Reserved2: WORD,
        DataOffset: DWORD,
        DataSelector: WORD,
        Reserved3: WORD,
        MxCsr: DWORD,
        MxCsr_Mask: DWORD,
        FloatRegisters: [8]M128A,
        XmmRegisters: [16]M128A,
        Reserved4: [96]BYTE,
    },
    else => @compileError("XMM_SAVE_AREA32 only defined on x86_64"),
};

pub const NEON128 = switch (native_arch) {
    .thumb => extern struct {
        Low: ULONGLONG,
        High: LONGLONG,
    },
    .aarch64 => extern union {
        DUMMYSTRUCTNAME: extern struct {
            Low: ULONGLONG,
            High: LONGLONG,
        },
        D: [2]f64,
        S: [4]f32,
        H: [8]WORD,
        B: [16]BYTE,
    },
    else => @compileError("NEON128 only defined on aarch64"),
};

pub const CONTEXT = switch (native_arch) {
    .x86 => extern struct {
        ContextFlags: DWORD,
        Dr0: DWORD,
        Dr1: DWORD,
        Dr2: DWORD,
        Dr3: DWORD,
        Dr6: DWORD,
        Dr7: DWORD,
        FloatSave: FLOATING_SAVE_AREA,
        SegGs: DWORD,
        SegFs: DWORD,
        SegEs: DWORD,
        SegDs: DWORD,
        Edi: DWORD,
        Esi: DWORD,
        Ebx: DWORD,
        Edx: DWORD,
        Ecx: DWORD,
        Eax: DWORD,
        Ebp: DWORD,
        Eip: DWORD,
        SegCs: DWORD,
        EFlags: DWORD,
        Esp: DWORD,
        SegSs: DWORD,
        ExtendedRegisters: [512]BYTE,
    },
    .x86_64 => extern struct {
        P1Home: DWORD64 align(16),
        P2Home: DWORD64,
        P3Home: DWORD64,
        P4Home: DWORD64,
        P5Home: DWORD64,
        P6Home: DWORD64,
        ContextFlags: DWORD,
        MxCsr: DWORD,
        SegCs: WORD,
        SegDs: WORD,
        SegEs: WORD,
        SegFs: WORD,
        SegGs: WORD,
        SegSs: WORD,
        EFlags: DWORD,
        Dr0: DWORD64,
        Dr1: DWORD64,
        Dr2: DWORD64,
        Dr3: DWORD64,
        Dr6: DWORD64,
        Dr7: DWORD64,
        Rax: DWORD64,
        Rcx: DWORD64,
        Rdx: DWORD64,
        Rbx: DWORD64,
        Rsp: DWORD64,
        Rbp: DWORD64,
        Rsi: DWORD64,
        Rdi: DWORD64,
        R8: DWORD64,
        R9: DWORD64,
        R10: DWORD64,
        R11: DWORD64,
        R12: DWORD64,
        R13: DWORD64,
        R14: DWORD64,
        R15: DWORD64,
        Rip: DWORD64,
        DUMMYUNIONNAME: extern union {
            FltSave: XMM_SAVE_AREA32,
            FloatSave: XMM_SAVE_AREA32,
            DUMMYSTRUCTNAME: extern struct {
                Header: [2]M128A,
                Legacy: [8]M128A,
                Xmm0: M128A,
                Xmm1: M128A,
                Xmm2: M128A,
                Xmm3: M128A,
                Xmm4: M128A,
                Xmm5: M128A,
                Xmm6: M128A,
                Xmm7: M128A,
                Xmm8: M128A,
                Xmm9: M128A,
                Xmm10: M128A,
                Xmm11: M128A,
                Xmm12: M128A,
                Xmm13: M128A,
                Xmm14: M128A,
                Xmm15: M128A,
            },
        },
        VectorRegister: [26]M128A,
        VectorControl: DWORD64,
        DebugControl: DWORD64,
        LastBranchToRip: DWORD64,
        LastBranchFromRip: DWORD64,
        LastExceptionToRip: DWORD64,
        LastExceptionFromRip: DWORD64,
    },
    .thumb => extern struct {
        ContextFlags: ULONG,
        R0: ULONG,
        R1: ULONG,
        R2: ULONG,
        R3: ULONG,
        R4: ULONG,
        R5: ULONG,
        R6: ULONG,
        R7: ULONG,
        R8: ULONG,
        R9: ULONG,
        R10: ULONG,
        R11: ULONG,
        R12: ULONG,
        Sp: ULONG,
        Lr: ULONG,
        Pc: ULONG,
        Cpsr: ULONG,
        Fpcsr: ULONG,
        Padding: ULONG,
        DUMMYUNIONNAME: extern union {
            Q: [16]NEON128,
            D: [32]ULONGLONG,
            S: [32]ULONG,
        },
        Bvr: [8]ULONG,
        Bcr: [8]ULONG,
        Wvr: [1]ULONG,
        Wcr: [1]ULONG,
        Padding2: [2]ULONG,
    },
    .aarch64 => extern struct {
        ContextFlags: ULONG align(16),
        Cpsr: ULONG,
        DUMMYUNIONNAME: extern union {
            DUMMYSTRUCTNAME: extern struct {
                X0: DWORD64,
                X1: DWORD64,
                X2: DWORD64,
                X3: DWORD64,
                X4: DWORD64,
                X5: DWORD64,
                X6: DWORD64,
                X7: DWORD64,
                X8: DWORD64,
                X9: DWORD64,
                X10: DWORD64,
                X11: DWORD64,
                X12: DWORD64,
                X13: DWORD64,
                X14: DWORD64,
                X15: DWORD64,
                X16: DWORD64,
                X17: DWORD64,
                X18: DWORD64,
                X19: DWORD64,
                X20: DWORD64,
                X21: DWORD64,
                X22: DWORD64,
                X23: DWORD64,
                X24: DWORD64,
                X25: DWORD64,
                X26: DWORD64,
                X27: DWORD64,
                X28: DWORD64,
                Fp: DWORD64,
                Lr: DWORD64,
            },
            X: [31]DWORD64,
        },
        Sp: DWORD64,
        Pc: DWORD64,
        V: [32]NEON128,
        Fpcr: DWORD,
        Fpsr: DWORD,
        Bcr: [8]DWORD,
        Bvr: [8]DWORD64,
        Wcr: [2]DWORD,
        Wvr: [2]DWORD64,
    },
    else => @compileError("CONTEXT is not defined for this architecture"),
};
pub const LPTHREAD_START_ROUTINE = *const fn (LPVOID) callconv(.winapi) DWORD;
pub const WNDENUMPROC = *const fn (HWND, LPARAM) callconv(.winapi) BOOL;
pub const FILE_BOTH_DIR_INFORMATION = extern struct {
    NextEntryOffset: ULONG,
    FileIndex: ULONG,
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    EndOfFile: LARGE_INTEGER,
    AllocationSize: LARGE_INTEGER,
    FileAttributes: ULONG,
    FileNameLength: ULONG,
    EaSize: ULONG,
    ShortNameLength: CHAR,
    ShortName: [12]WCHAR,
    FileName: [1]WCHAR,
};
pub const FILE_BOTH_DIRECTORY_INFORMATION = FILE_BOTH_DIR_INFORMATION;
pub const BYTE = u8;
pub const LPBYTE = *u8;
pub const CHAR = u8;
pub const UCHAR = u8;
pub const FLOAT = f32;
pub const HANDLE = *anyopaque;
pub const PHANDLE = *HANDLE;
pub const HCRYPTPROV = ULONG_PTR;
pub const ATOM = u16;
pub const HBRUSH = *opaque {};
pub const HCURSOR = *opaque {};
pub const HICON = *opaque {};
pub const HINSTANCE = *opaque {};
pub const HMENU = *opaque {};
pub const HMODULE = *opaque {};
pub const HWND = *opaque {};
pub const HDC = *opaque {};
pub const HGLRC = *opaque {};
pub const FARPROC = *opaque {};
pub const PROC = *opaque {};
pub const INT = c_int;
pub const LPCSTR = [*:0]const CHAR;
pub const LPCVOID = *const anyopaque;
pub const LPSTR = [*:0]CHAR;
pub const LPVOID = *anyopaque;
pub const LPWSTR = [*:0]WCHAR;
pub const LPCWSTR = [*:0]const WCHAR;
pub const PVOID = *anyopaque;
pub const PWSTR = [*:0]WCHAR;
pub const PCWSTR = [*:0]const WCHAR;
/// Allocated by SysAllocString, freed by SysFreeString
pub const BSTR = [*:0]WCHAR;
pub const SIZE_T = usize;
pub const PSIZE_T = *SIZE_T;
pub const UINT = c_uint;
pub const ULONG_PTR = usize;
pub const LONG_PTR = isize;
pub const DWORD_PTR = ULONG_PTR;
pub const WCHAR = u16;
pub const WORD = u16;
pub const DWORD = u32;
pub const DWORD64 = u64;
pub const LARGE_INTEGER = i64;
pub const PLARGE_INTEGER = *LARGE_INTEGER;
pub const ULARGE_INTEGER = u64;
pub const USHORT = u16;
pub const SHORT = i16;
pub const ULONG = u32;
pub const PULONG = *ULONG;
pub const LONG = i32;
pub const ULONG64 = u64;
pub const ULONGLONG = u64;
pub const LONGLONG = i64;
pub const PULONGLONG = *u64;
pub const LANGID = c_ushort;
pub const COLORREF = DWORD;

pub const LPARAM = LONG_PTR;

pub const OBJ_PROTECT_CLOSE = 0x00000001;
pub const OBJ_INHERIT = 0x00000002;
pub const OBJ_AUDIT_OBJECT_CLOSE = 0x00000004;
pub const OBJ_NO_RIGHTS_UPGRADE = 0x00000008;
pub const OBJ_PERMANENT = 0x00000010;
pub const OBJ_EXCLUSIVE = 0x00000020;
pub const OBJ_CASE_INSENSITIVE = 0x00000040;
pub const OBJ_OPENIF = 0x00000080;
pub const OBJ_OPENLINK = 0x00000100;
pub const OBJ_KERNEL_HANDLE = 0x00000200;
pub const OBJ_FORCE_ACCESS_CHECK = 0x00000400;
pub const OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800;
pub const OBJ_DONT_REPARSE = 0x00001000;
pub const OBJ_VALID_ATTRIBUTES = 0x00001ff2;

pub const AI = packed struct(u32) {
    PASSIVE: bool = false,
    CANONNAME: bool = false,
    NUMERICHOST: bool = false,
    NUMERICSERV: bool = false,
    DNS_ONLY: bool = false,
    _5: u3 = 0,
    ALL: bool = false,
    _9: u1 = 0,
    ADDRCONFIG: bool = false,
    V4MAPPED: bool = false,
    _12: u2 = 0,
    NON_AUTHORITATIVE: bool = false,
    SECURE: bool = false,
    RETURN_PREFERRED_NAMES: bool = false,
    FQDN: bool = false,
    FILESERVER: bool = false,
    DISABLE_IDN_ENCODING: bool = false,
    _20: u10 = 0,
    RESOLUTION_HANDLE: bool = false,
    EXTENDED: bool = false,
};

pub const ADDRESS_FAMILY = u16;
pub const sockaddr = extern struct {
    family: ADDRESS_FAMILY,
    data: [14]u8,

    pub const SS_MAXSIZE = 128;
    pub const storage = extern struct {
        family: ADDRESS_FAMILY align(8),
        padding: [SS_MAXSIZE - @sizeOf(ADDRESS_FAMILY)]u8 = undefined,
    };

    /// IPv4 socket address
    pub const in = extern struct {
        family: ADDRESS_FAMILY = AF.INET,
        port: USHORT,
        addr: u32,
        zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    /// IPv6 socket address
    pub const in6 = extern struct {
        family: ADDRESS_FAMILY = AF.INET6,
        port: USHORT,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

    /// UNIX domain socket address
    pub const un = extern struct {
        family: ADDRESS_FAMILY = AF.UNIX,
        path: [108]u8,
    };
};

pub const addrinfo = addrinfoa;

pub const addrinfoa = extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};
pub const WSABUF = extern struct {
    len: ULONG,
    buf: [*]u8,
};
pub const LPWSAOVERLAPPED_COMPLETION_ROUTINE = *const fn (
    dwError: u32,
    cbTransferred: u32,
    lpOverlapped: *OVERLAPPED,
    dwFlags: u32,
) callconv(.winapi) void;

pub const WSAPOLLFD = pollfd;

pub const pollfd = extern struct {
    fd: SOCKET,
    events: SHORT,
    revents: SHORT,
};
pub const IO_STATUS_BLOCK = extern struct {
    // "DUMMYUNIONNAME" expands to "u"
    u: extern union {
        Status: NTSTATUS,
        Pointer: ?*anyopaque,
    },
    Information: ULONG_PTR,
};
pub const PIO_STATUS_BLOCK = *IO_STATUS_BLOCK;
pub const PIO_APC_ROUTINE = *const fn (PVOID, *IO_STATUS_BLOCK, ULONG) callconv(.winapi) void;
pub const WinsockError = u16;
pub const WAIT_FAILED = 0xffff_ffff;

pub const MEM_COMMIT = 0x1000;
pub const MEM_RESERVE = 0x2000;
pub const MEM_FREE = 0x10000;
pub const MEM_RESET = 0x80000;
pub const MEM_RESET_UNDO = 0x1000000;
pub const MEM_LARGE_PAGES = 0x20000000;
pub const MEM_PHYSICAL = 0x400000;
pub const MEM_TOP_DOWN = 0x100000;
pub const MEM_WRITE_WATCH = 0x200000;
pub const MEM_RESERVE_PLACEHOLDER = 0x00040000;
pub const MEM_PRESERVE_PLACEHOLDER = 0x00000400;

pub const MEM_COALESCE_PLACEHOLDERS = 0x1;
pub const MEM_RESERVE_PLACEHOLDERS = 0x2;
pub const MEM_DECOMMIT = 0x4000;
pub const MEM_RELEASE = 0x8000;

pub const PAGE_EXECUTE = 0x10;
pub const PAGE_EXECUTE_READ = 0x20;
pub const PAGE_EXECUTE_READWRITE = 0x40;
pub const PAGE_EXECUTE_WRITECOPY = 0x80;
pub const PAGE_NOACCESS = 0x01;
pub const PAGE_READONLY = 0x02;
pub const PAGE_READWRITE = 0x04;
pub const PAGE_WRITECOPY = 0x08;
pub const PAGE_TARGETS_INVALID = 0x40000000;
pub const PAGE_TARGETS_NO_UPDATE = 0x40000000;
pub const PAGE_GUARD = 0x100;
pub const PAGE_NOCACHE = 0x200;
pub const PAGE_WRITECOMBINE = 0x400;

pub const SECURITY_NT_AUTHORITY = 5;
pub const DOMAIN_ALIAS_RID_ADMINS = 544;
pub const SECURITY_BUILTIN_DOMAIN_RID = 32;

pub const READ_CONTROL = 0x00020000;

pub const STANDARD_RIGHTS_REQUIRED = 0x000F0000;
pub const SYNCHRONIZE = 0x00100000;

pub const STANDARD_RIGHTS_READ = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

pub const PROCESS_TERMINATE = 0x0001;
pub const PROCESS_CREATE_THREAD = 0x0002;
pub const PROCESS_SET_SESSIONID = 0x0004;
pub const PROCESS_VM_OPERATION = 0x0008;
pub const PROCESS_VM_READ = 0x0010;
pub const PROCESS_VM_WRITE = 0x0020;
pub const PROCESS_DUP_HANDLE = 0x0040;
pub const PROCESS_CREATE_PROCESS = 0x0080;
pub const PROCESS_SET_QUOTA = 0x0100;
pub const PROCESS_SET_INFORMATION = 0x0200;
pub const PROCESS_QUERY_INFORMATION = 0x0400;
pub const PROCESS_SUSPEND_RESUME = 0x0800;
pub const PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | SPECIFIC_RIGHTS_ALL;

pub const JOB_OBJECT_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F;

pub const STANDARD_RIGHTS_ALL = 0x001F0000;
pub const SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
pub const PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT = 0x00000100;

pub const OBJECT_INFORMATION_CLASS = enum(c_int) {
    ObjectBasicInformation, // q: OBJECT_BASIC_INFORMATION
    ObjectNameInformation, // q: OBJECT_NAME_INFORMATION
    ObjectTypeInformation, // q: OBJECT_TYPE_INFORMATION
    ObjectTypesInformation, // q: OBJECT_TYPES_INFORMATION
    ObjectHandleFlagInformation, // qs: OBJECT_HANDLE_FLAG_INFORMATION
    ObjectSessionInformation, // s: void // change object session // (requires SeTcbPrivilege)
    ObjectSessionObjectInformation, // s: void // change object session // (requires SeTcbPrivilege)
    ObjectSetRefTraceInformation, // since 25H2
    MaxObjectInfoClass
};

pub const FSINFOCLASS = enum(c_int) {
    FileFsVolumeInformation = 1,            // q: FILE_FS_VOLUME_INFORMATION
    FileFsLabelInformation,                 // s: FILE_FS_LABEL_INFORMATION // SeManageVolumePrivilege
    FileFsSizeInformation,                  // q: FILE_FS_SIZE_INFORMATION
    FileFsDeviceInformation,                // q: FILE_FS_DEVICE_INFORMATION
    FileFsAttributeInformation,             // q: FILE_FS_ATTRIBUTE_INFORMATION
    FileFsControlInformation,               // qs: FILE_FS_CONTROL_INFORMATION // SeManageVolumePrivilege
    FileFsFullSizeInformation,              // q: FILE_FS_FULL_SIZE_INFORMATION
    FileFsObjectIdInformation,              // qs: FILE_FS_OBJECTID_INFORMATION // SeRestorePrivilege
    FileFsDriverPathInformation,            // q: FILE_FS_DRIVER_PATH_INFORMATION
    FileFsVolumeFlagsInformation,           // qs: FILE_FS_VOLUME_FLAGS_INFORMATION // SeManageVolumePrivilege // 10
    FileFsSectorSizeInformation,            // q: FILE_FS_SECTOR_SIZE_INFORMATION // since WIN8
    FileFsDataCopyInformation,              // q: FILE_FS_DATA_COPY_INFORMATION
    FileFsMetadataSizeInformation,          // q: FILE_FS_METADATA_SIZE_INFORMATION // since THRESHOLD
    FileFsFullSizeInformationEx,            // q: FILE_FS_FULL_SIZE_INFORMATION_EX // since REDSTONE5
    FileFsGuidInformation,                  // q: FILE_FS_GUID_INFORMATION // since 23H2
    FileFsMaximumInformation
};
pub const FS_INFORMATION_CLASS = FSINFOCLASS;

pub const FILE_INFORMATION_CLASS = enum(c_int) {
    FileDirectoryInformation = 1,                   // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileFullDirectoryInformation,                   // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBothDirectoryInformation,                   // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBasicInformation,                           // qs: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileStandardInformation,                        // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
    FileInternalInformation,                        // q: FILE_INTERNAL_INFORMATION
    FileEaInformation,                              // q: FILE_EA_INFORMATION (requires FILE_READ_EA)
    FileAccessInformation,                          // q: FILE_ACCESS_INFORMATION
    FileNameInformation,                            // q: FILE_NAME_INFORMATION
    FileRenameInformation,                          // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
    FileLinkInformation,                            // s: FILE_LINK_INFORMATION
    FileNamesInformation,                           // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileDispositionInformation,                     // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
    FilePositionInformation,                        // qs: FILE_POSITION_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileFullEaInformation,                          // q: FILE_FULL_EA_INFORMATION (requires FILE_READ_EA)
    FileModeInformation,                            // qs: FILE_MODE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileAlignmentInformation,                       // q: FILE_ALIGNMENT_INFORMATION
    FileAllInformation,                             // q: FILE_ALL_INFORMATION
    FileAllocationInformation,                      // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
    FileEndOfFileInformation,                       // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
    FileAlternateNameInformation,                   // q: FILE_NAME_INFORMATION
    FileStreamInformation,                          // q: FILE_STREAM_INFORMATION
    FilePipeInformation,                            // qs: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FilePipeLocalInformation,                       // q: FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation,                      // qs: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileMailslotQueryInformation,                   // q: FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation,                     // s: FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation,                     // q: FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation,                        // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileCompletionInformation,                      // s: FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation,                     // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
    FileQuotaInformation,                           // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileReparsePointInformation,                    // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileNetworkOpenInformation,                     // q: FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation,                    // q: FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation,                        // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
    FileIdBothDirectoryInformation,                 // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileIdFullDirectoryInformation,                 // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileValidDataLengthInformation,                 // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
    FileShortNameInformation,                       // s: FILE_NAME_INFORMATION (requires DELETE) // 40
    FileIoCompletionNotificationInformation,        // qs: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since VISTA
    FileIoStatusBlockRangeInformation,              // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
    FileIoPriorityHintInformation,                  // qs: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
    FileSfioReserveInformation,                     // qs: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
    FileSfioVolumeInformation,                      // q: FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation,                        // q: FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation,             // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation,                  // q: FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation,             // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation,             // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
    FileIsRemoteDeviceInformation,                  // q: FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,                          // q:
    FileNumaNodeInformation,                        // q: FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation,                    // q: FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation,                  // q: FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck,         // s: FILE_RENAME_INFORMATION // (kernel-mode only) // since WIN8
    FileLinkInformationBypassAccessCheck,           // s: FILE_LINK_INFORMATION // (kernel-mode only)
    FileVolumeNameInformation,                      // q: FILE_VOLUME_NAME_INFORMATION
    FileIdInformation,                              // q: FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation,                 // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
    FileReplaceCompletionInformation,               // s: FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation,                  // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation,             // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
    FileDispositionInformationEx,                   // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
    FileRenameInformationEx,                        // s: FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck,       // s: FILE_RENAME_INFORMATION_EX // (kernel-mode only)
    FileDesiredStorageClassInformation,             // qs: FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation,                            // q: FILE_STAT_INFORMATION
    FileMemoryPartitionInformation,                 // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation,                          // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
    FileCaseSensitiveInformation,                   // qs: FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx,                          // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck,         // s: FILE_LINK_INFORMATION_EX // (kernel-mode only)
    FileStorageReserveIdInformation,                // qs: FILE_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck,   // qs: FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation,                     // qs: FILE_KNOWN_FOLDER_INFORMATION // since WIN11
    FileStatBasicInformation,                       // qs: FILE_STAT_BASIC_INFORMATION // since 23H2
    FileId64ExtdDirectoryInformation,               // q: FILE_ID_64_EXTD_DIR_INFORMATION
    FileId64ExtdBothDirectoryInformation,           // q: FILE_ID_64_EXTD_BOTH_DIR_INFORMATION
    FileIdAllExtdDirectoryInformation,              // q: FILE_ID_ALL_EXTD_DIR_INFORMATION
    FileIdAllExtdBothDirectoryInformation,          // q: FILE_ID_ALL_EXTD_BOTH_DIR_INFORMATION
    FileStreamReservationInformation,               // q: FILE_STREAM_RESERVATION_INFORMATION // since 24H2
    FileMupProviderInfo,                            // qs: MUP_PROVIDER_INFORMATION
    FileMaximumInformation
};

pub const PROCESSINFOCLASS = enum(c_int) {
    ProcessBasicInformation = 0,                    // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits,                             // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters,                              // q: IO_COUNTERS
    ProcessVmCounters,                              // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes,                                   // q: KERNEL_USER_TIMES
    ProcessBasePriority,                            // s: KPRIORITY
    ProcessRaisePriority,                           // s: ULONG
    ProcessDebugPort,                               // q: HANDLE
    ProcessExceptionPort,                           // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken,                             // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation,                          // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize,                                 // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode,                    // qs: ULONG
    ProcessIoPortHandlers,                          // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
    ProcessPooledUsageAndLimits,                    // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch,                         // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL,                            // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup,               // s: BOOLEAN
    ProcessPriorityClass,                           // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information,                         // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount,                             // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask,                            // qs: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost,                           // qs: ULONG
    ProcessDeviceMap,                               // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation,                      // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation,                   // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information,                        // q: ULONG_PTR
    ProcessImageFileName,                           // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled,                   // q: ULONG
    ProcessBreakOnTermination,                      // qs: ULONG
    ProcessDebugObjectHandle,                       // q: HANDLE // 30
    ProcessDebugFlags,                              // qs: ULONG
    ProcessHandleTracing,                           // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority,                              // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags,                            // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation,                          // qs: PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie,                                  // q: ULONG
    ProcessImageInformation,                        // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime,                               // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority,                            // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback,                 // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation,                   // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx,                       // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32,                      // q: UNICODE_STRING
    ProcessImageFileMapping,                        // q: HANDLE (input)
    ProcessAffinityUpdateMode,                      // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode,                    // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation,                        // q: USHORT[]
    ProcessTokenVirtualizationEnabled,              // s: ULONG
    ProcessConsoleHostProcess,                      // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation,                       // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation,                       // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy,                        // qs: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,         // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode,                      // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount,                          // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles,                       // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl,                       // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable,                             // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode,                   // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation,                  // q: UNICODE_STRING // 60
    ProcessProtectionInformation,                   // q: PS_PROTECTION
    ProcessMemoryExhaustion,                        // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation,                        // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation,                  // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation,                // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved1Information
    ProcessAllowedCpuSetsInformation,               // qs: SYSTEM_CPU_SET_INFORMATION[5] // ProcessReserved2Information
    ProcessSubsystemProcess,                        // s: void // EPROCESS->SubsystemProcess
    ProcessJobMemoryInformation,                    // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate,                               // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose,    // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,                    // q: PROCESS_IUM_CHALLENGE_RESPONSE
    ProcessChildProcessInformation,                 // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation,         // q: BOOLEAN; s: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation,                    // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues,                            // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
    ProcessPowerThrottlingState,                    // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessActivityThrottlePolicy,                  // qs: PROCESS_ACTIVITY_THROTTLE_POLICY // ProcessReserved3Information
    ProcessWin32kSyscallFilterInformation,          // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets,             // s: BOOLEAN // 80
    ProcessWakeInformation,                         // q: PROCESS_WAKE_INFORMATION // (kernel-mode only)
    ProcessEnergyTrackingState,                     // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory,          // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,                 // q: ULONG
    ProcessTelemetryCoverage,                       // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging,                // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation,                       // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection,                            // q: HANDLE
    ProcessDebugAuthInformation,                    // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
    ProcessSystemResourceManagement,                // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber,                          // q: ULONGLONG
    ProcessLoaderDetour,                            // qs: Obsolete // since RS5
    ProcessSecurityDomainInformation,               // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation,       // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging,                           // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation,                   // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation,              // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation,          // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation,                // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets,            // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges,      // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange,                       // s: Obsolete // since WIN11
    ProcessApplyStateChange,                        // s: Obsolete
    ProcessEnableOptionalXStateFeatures,            // s: ULONG64 // EnableProcessOptionalXStateFeatures
    ProcessAltPrefetchParam,                        // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,                     // s: HANDLE
    ProcessPriorityClassEx,                         // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation,                   // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority,                     // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority,                   // q: ULONG
    ProcessSchedulerSharedData,                     // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters,                       // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue,               // q: PROCESS_TEB_VALUE_INFORMATION // NtCurrentProcess
    ProcessEnclaveAddressSpaceRestriction,          // qs: // since 25H2
    ProcessAvailableCpus,                           // q: PROCESS_AVAILABLE_CPUS_INFORMATION
    MaxProcessInfoClass
};

pub const THREADINFOCLASS = enum(c_int) {
    ThreadBasicInformation = 0,                     // q: THREAD_BASIC_INFORMATION
    ThreadTimes,                                    // q: KERNEL_USER_TIMES
    ThreadPriority,                                 // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority,                             // s: KPRIORITY
    ThreadAffinityMask,                             // s: KAFFINITY
    ThreadImpersonationToken,                       // s: HANDLE
    ThreadDescriptorTableEntry,                     // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup,                // s: BOOLEAN
    ThreadEventPair,                                // q: Obsolete
    ThreadQuerySetWin32StartAddress,                // q: PVOID
    ThreadZeroTlsCell,                              // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount,                         // q: LARGE_INTEGER
    ThreadAmILastThread,                            // q: ULONG
    ThreadIdealProcessor,                           // s: ULONG
    ThreadPriorityBoost,                            // qs: ULONG
    ThreadSetTlsArrayAddress,                       // s: ULONG_PTR
    ThreadIsIoPending,                              // q: ULONG
    ThreadHideFromDebugger,                         // q: BOOLEAN; s: void
    ThreadBreakOnTermination,                       // qs: ULONG
    ThreadSwitchLegacyState,                        // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated,                             // q: ULONG // 20
    ThreadLastSystemCall,                           // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority,                               // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime,                                // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
    ThreadPagePriority,                             // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority,                       // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation,                           // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,                               // q: Obsolete
    ThreadCSwitchPmu,                               // q: Obsolete
    ThreadWow64Context,                             // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation,                         // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation,                           // q: THREAD_UMS_INFORMATION // Obsolete
    ThreadCounterProfiling,                         // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx,                         // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation,                 // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount,                             // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy,                   // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId,                              // q: GUID
    ThreadNameInformation,                          // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
    ThreadSelectedCpuSets,                          // q: ULONG[]
    ThreadSystemThreadInformation,                  // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity,                      // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,                    // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity,                  // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
    ThreadWorkOnBehalfTicket,                       // q: ALPC_WORK_ON_BEHALF_TICKET // RTL_WORK_ON_BEHALF_TICKET_EX // NtCurrentThread
    ThreadSubsystemInformation,                     // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,                      // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer,                          // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory,           // s: MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState,                     // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
    ThreadWorkloadClass,                            // q: THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange,                        // s: Obsolete // since WIN11
    ThreadApplyStateChange,                         // s: Obsolete
    ThreadStrongerBadHandleChecks,                  // s: ULONG // NtCurrentThread // since 22H1
    ThreadEffectiveIoPriority,                      // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority,                    // q: ULONG
    ThreadUpdateLockOwnership,                      // s: THREAD_LOCK_OWNERSHIP // since 24H2
    ThreadSchedulerSharedDataSlot,                  // q: SCHEDULER_SHARED_DATA_SLOT_INFORMATION
    ThreadTebInformationAtomic,                     // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
    ThreadIndexInformation,                         // q: THREAD_INDEX_INFORMATION
    MaxThreadInfoClass
};

pub const SYSTEM_INFORMATION_CLASS = enum(c_int) {
    SystemBasicInformation = 0,                             // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,                             // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,                           // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation,                             // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation,                                  // q: not implemented
    SystemProcessInformation,                               // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation,                             // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation,                                // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation,                  // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation,                                 // qs: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation,                              // q: SYSTEM_CALL_TIME_INFORMATION // not implemented // 10
    SystemModuleInformation,                                // q: RTL_PROCESS_MODULES
    SystemLocksInformation,                                 // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation,                            // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation,                             // q: not implemented
    SystemNonPagedPoolInformation,                          // q: not implemented
    SystemHandleInformation,                                // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation,                                // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation,                              // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation,                           // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation,                                // q: not implemented // 20
    SystemFileCacheInformation,                             // qs: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation,                               // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation,                             // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation,                           // qs: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation,                            // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemLoadGdiDriverInformation,                         // s: (kernel-mode only)
    SystemUnloadGdiDriverInformation,                       // s: (kernel-mode only)
    SystemTimeAdjustmentInformation,                        // qs: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation,                         // q: SYSTEM_MEMORY_USAGE_INFORMATION // not implemented
    SystemMirrorMemoryInformation,                          // qs: (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation,                      // qs: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0,                                        // q: not implemented
    SystemExceptionInformation,                             // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation,                        // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation,                        // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation,                         // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation,                         // qs: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation,                    // s: (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeparation,                               // s: (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation,                     // s: UNICODE_STRING (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation,                  // s: UNICODE_STRING (requires SeDebugPrivilege)
    SystemProcessorIdleInformation,                         // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation,                          // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation,                       // qs: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation,                             // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification,                             // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate,                                    // q: not implemented
    SystemSessionDetach,                                    // q: not implemented
    SystemSessionInformation,                               // q: not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation,                            // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation,                              // qs: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend,                              // qs: (kernel-mode only)
    SystemSessionProcessInformation,                        // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace,                       // qs: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap,                                 // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation,                            // qs: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation,                       // q: SYSTEM_EXTENDED_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment,                   // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage,                                   // qs: ULONG
    SystemNumaAvailableMemory,                              // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation,                        // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation,                        // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation,                    // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation,                        // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation,                      // q: ULONG
    SystemBigPoolInformation,                               // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation,                     // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation,                              // qs: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode,                               // q: ULONG // 70
    SystemWatchdogTimerHandler,                             // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation,                         // qs: out: SYSTEM_WATCHDOG_TIMER_INFORMATION (EX in: ULONG WATCHDOG_INFORMATION_CLASS) // NtQuerySystemInformationEx
    SystemLogicalProcessorInformation,                      // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemWow64SharedInformationObsolete,                   // q: not implemented
    SystemRegisterFirmwareTableInformationHandler,          // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation,                         // q: SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx,                              // q: RTL_PROCESS_MODULE_INFORMATION_EX // since VISTA
    SystemVerifierTriageInformation,                        // q: not implemented
    SystemSuperfetchInformation,                            // qs: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation,                            // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation,                // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege) // NtQuerySystemInformationEx
    SystemProcessorIdleCycleTimeInformation,                // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemVerifierCancellationInformation,                  // q: SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx,                      // q: not implemented
    SystemRefTraceInformation,                              // qs: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation,                           // qs: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation,                             // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation,                             // s: HANDLE (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation,                       // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation,                            // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx,                            // qs: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation,                              // qs: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation,             // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation,                              // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation,                         // q: SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation,                        // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation,                       // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation,                            // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution,                 // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 100
    SystemNumaProximityNodeInformation,                     // qs: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation,                       // qs: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation,                         // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation,              // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION (requires SeLoadDriverPrivilege)
    SystemProcessorBrandString,                             // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation,                        // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation,              // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // NtQuerySystemInformationEx // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation,                    // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx
    SystemStoreInformation,                                 // qs: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString,                             // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue,                                 // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation,                               // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation,                              // qs: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation,                           // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts,                                // q: SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation,                         // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation,                        // q: BOOT_ENTROPY_NT_RESULT // ExQueryBootEntropyInformation
    SystemVerifierCountersInformation,                      // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx,                           // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx,                          // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation,                          // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber) // NtQuerySystemInformationEx
    SystemAcpiAuditInformation,                             // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation,                      // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation,               // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation,                        // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation,                          // qs: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation,                   // qs: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,                               // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemProcessorProfileControlArea,                      // qs: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation,                 // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation,                // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation,                               // qs: SYSTEM_CONSOLE_INFORMATION // (requires SeLoadDriverPrivilege)
    SystemPlatformBinaryInformation,                        // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation,                                // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation,              // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation,                            // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation,                 // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation,                        // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation,                         // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation,                              // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx,                // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // since WINBLUE
    SystemCriticalProcessErrorLogInformation,               // q: CRITICAL_PROCESS_EXCEPTION_DATA
    SystemSecureBootPolicyInformation,                      // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx,                            // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation,                            // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,             // qs: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemPortableWorkspaceEfiLauncherInformation,          // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation,                           // q: SYSTEM_EXTENDED_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx,                      // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation,                          // q: SYSTEM_BOOT_METADATA_INFORMATION // (requires SeTcbPrivilege) // 150
    SystemSoftRebootInformation,                            // q: SYSTEM_SOFT_REBOOT_INFORMATION
    SystemElamCertificateInformation,                       // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation,                     // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation,                     // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation,                // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation,                                  // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation,                         // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation,                // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation,                      // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation,                   // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // NtQuerySystemInformationEx // 160
    SystemVmGenerationCountInformation,                     // s: PHYSICAL_ADDRESS (kernel-mode only) (vmgencounter.sys)
    SystemTrustedPlatformModuleInformation,                 // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags,                              // q: SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation,                   // qs: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation,                      // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,  // q: SYSTEM_HARDWARE_SECURITY_TEST_INTERFACE_RESULTS_INFORMATION
    SystemSingleModuleInformation,                          // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation,                        // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation,                         // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation,                      // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation,                  // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,               // q:
    SystemAffinitizedInterruptProcessorInformation,         // q: KAFFINITY_EX // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation,                              // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation,                                // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation,                             // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,                             // s:
    SystemSecureKernelProfileInformation,                   // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation,         // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // NtQuerySystemInformationEx // since REDSTONE
    SystemInterruptSteeringInformation,                     // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemSupportedProcessorArchitectures,                  // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 180
    SystemMemoryUsageInformation,                           // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation,              // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation,                        // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition,                            // qs: (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed,                           // s: ULONG
    SystemActivityModerationExeState,                       // s: SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings,                   // q: SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,             // qs: NtQuerySystemInformationEx
    SystemCodeIntegrityUnlockInformation,                   // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,                        // s: SYSTEM_INTEGRITY_QUOTA_INFORMATION (requires SeDebugPrivilege)
    SystemFlushInformation,                                 // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation,                     // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,                  // qs: NtQuerySystemInformationEx // (q: requires SeDebugPrivilege) (s: requires SeTcbPrivilege)
    SystemWriteConstraintInformation,                       // q: SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation,                        // q: SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation,                  // q: SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,               // q:
    SystemCodeIntegrityVerificationInformation,             // q: SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation,                     // q: SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation,                    // q: SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation,                        // q: SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation,                  // q: SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation,                // q: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation,               // q: SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation,                            // qs: SYSTEM_LEAP_SECOND_INFORMATION // (s: requires SeSystemtimePrivilege)
    SystemFlags2Information,                                // q: SYSTEM_FLAGS_INFORMATION // (s: requires SeDebugPrivilege)
    SystemSecurityModelInformation,                         // q: SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,           // qs: NtQuerySystemInformationEx
    SystemFeatureConfigurationInformation,                  // q: in: SYSTEM_FEATURE_CONFIGURATION_QUERY, out: SYSTEM_FEATURE_CONFIGURATION_INFORMATION; s: SYSTEM_FEATURE_CONFIGURATION_UPDATE // NtQuerySystemInformationEx // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation,           // q: in: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_REQUEST, out: SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION // NtQuerySystemInformationEx
    SystemFeatureUsageSubscriptionInformation,              // q: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS; s: SYSTEM_FEATURE_USAGE_SUBSCRIPTION_UPDATE
    SystemSecureSpeculationControlInformation,              // q: SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation,                            // qs: // since 20H2
    SystemFwRamdiskInformation,                             // q: SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,                      // q: SYSTEM_WHEA_IPMI_HARDWARE_INFORMATION
    SystemDifSetRuleClassInformation,                       // s: SYSTEM_DIF_VOLATILE_INFORMATION (requires SeDebugPrivilege)
    SystemDifClearRuleClassInformation,                     // s: NULL (requires SeDebugPrivilege)
    SystemDifApplyPluginVerificationOnDriver,               // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege)
    SystemDifRemovePluginVerificationOnDriver,              // q: SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION (requires SeDebugPrivilege) // 220
    SystemShadowStackInformation,                           // q: SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation,                          // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx
    SystemPoolLimitInformation,                             // q: SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege) // NtQuerySystemInformationEx
    SystemCodeIntegrityAddDynamicStore,                     // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemCodeIntegrityClearDynamicStores,                  // q: CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners
    SystemDifPoolTrackingInformation,                       // s: SYSTEM_DIF_POOL_TRACKING_INFORMATION (requires SeDebugPrivilege)
    SystemPoolZeroingInformation,                           // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation,                           // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2,                          // qs: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2,                 // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation,           // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor) // NtQuerySystemInformationEx
    SystemXfgCheckFailureInformation,                       // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation,                            // q: SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation,                     // q: SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation,                   // q: SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation,                           // q: SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,                  // qs: NtQuerySystemInformationEx
    SystemOriginalImageFeatureInformation,                  // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaInformation,                            // q: SYSTEM_MEMORY_NUMA_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    SystemMemoryNumaPerformanceInformation,                 // q: SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_INPUT, SYSTEM_MEMORY_NUMA_PERFORMANCE_INFORMATION_OUTPUT // since 24H2 // 240
    SystemCodeIntegritySignedPoliciesFullInformation,       // qs: NtQuerySystemInformationEx
    SystemSecureCoreInformation,                            // qs: SystemSecureSecretsInformation
    SystemTrustedAppsRuntimeInformation,                    // q: SYSTEM_TRUSTEDAPPS_RUNTIME_INFORMATION
    SystemBadPageInformationEx,                             // q: SYSTEM_BAD_PAGE_INFORMATION
    SystemResourceDeadlockTimeout,                          // q: ULONG
    SystemBreakOnContextUnwindFailureInformation,           // q: ULONG (requires SeDebugPrivilege)
    SystemOslRamdiskInformation,                            // q: SYSTEM_OSL_RAMDISK_INFORMATION
    SystemCodeIntegrityPolicyManagementInformation,         // q: SYSTEM_CODEINTEGRITYPOLICY_MANAGEMENT // since 25H2
    SystemMemoryNumaCacheInformation,                       // q: SYSTEM_MEMORY_NUMA_CACHE_INFORMATION
    SystemProcessorFeaturesBitMapInformation,               // q: ULONG64[2] // RTL_BITMAP_EX // RtlInitializeBitMapEx // 250
    SystemRefTraceInformationEx,                            // q: SYSTEM_REF_TRACE_INFORMATION_EX
    SystemBasicProcessInformation,                          // q: SYSTEM_BASICPROCESS_INFORMATION
    SystemHandleCountInformation,                           // q: SYSTEM_HANDLECOUNT_INFORMATION
    SystemRuntimeAttestationReport,                         // q: SYSTEM_RUNTIME_REPORT_INPUT
    SystemPoolTagInformation2,                              // q: SYSTEM_POOLTAG_INFORMATION2 // since 26H1
    MaxSystemInfoClass
};

pub const TOKEN_ASSIGN_PRIMARY = 0x0001;
pub const TOKEN_DUPLICATE = 0x0002;
pub const TOKEN_IMPERSONATE = 0x0004;
pub const TOKEN_QUERY = 0x0008;
pub const TOKEN_QUERY_SOURCE = 0x0010;
pub const TOKEN_ADJUST_PRIVILEGES = 0x0020;
pub const TOKEN_ADJUST_GROUPS = 0x0040;
pub const TOKEN_ADJUST_DEFAULT = 0x0080;
pub const TOKEN_ADJUST_SESSIONID = 0x0100;

pub const TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;

pub const TOKEN_INFORMATION_CLASS = enum(c_int) {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    TokenProcessTrustLevel,
    TokenPrivateNameSpace,
    TokenSingletonAttributes,
    TokenBnoIsolation,
    TokenChildProcessFlags,
    TokenIsLessPrivilegedAppContainer,
    TokenIsSandboxed,
    MaxTokenInfoClass, // MaxTokenInfoClass should always be the last enum
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const MAX_PROTOCOL_CHAIN = 7;
pub const WSAPROTOCOLCHAIN = extern struct {
    ChainLen: c_int,
    ChainEntries: [MAX_PROTOCOL_CHAIN]DWORD,
};

pub const SOCKET = *opaque {};

pub const WSAPROTOCOL_LEN = 255;
pub const WSAPROTOCOL_INFOW = extern struct {
    dwServiceFlags1: DWORD,
    dwServiceFlags2: DWORD,
    dwServiceFlags3: DWORD,
    dwServiceFlags4: DWORD,
    dwProviderFlags: DWORD,
    ProviderId: GUID,
    dwCatalogEntryId: DWORD,
    ProtocolChain: WSAPROTOCOLCHAIN,
    iVersion: c_int,
    iAddressFamily: c_int,
    iMaxSockAddr: c_int,
    iMinSockAddr: c_int,
    iSocketType: c_int,
    iProtocol: c_int,
    iProtocolMaxOffset: c_int,
    iNetworkByteOrder: c_int,
    iSecurityScheme: c_int,
    dwMessageSize: DWORD,
    dwProviderReserved: DWORD,
    szProtocol: [WSAPROTOCOL_LEN + 1]WCHAR,
};

pub const WSADESCRIPTION_LEN = 256;
pub const WSASYS_STATUS_LEN = 128;
pub const WSADATA = if (@sizeOf(usize) == @sizeOf(u64))
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
    }
else
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
    };

pub const SECTION_IMAGE_INFORMATION = extern struct {
    TransferAddress: ?PVOID,
    ZeroBits: ULONG,
    MaximumStackSize: SIZE_T,
    CommittedStackSize: SIZE_T,
    SubSystemType: ULONG,
    U0: extern union {
        S: extern struct {
            SubSystemMinorVersion: USHORT,
            SubSystemMajorVersion: USHORT,
        },
        SubSystemVersion: ULONG,
    },
    U1: extern union {
        S: extern struct {
            MajorOperatingSystemVersion: USHORT,
            MinorOperatingSystemVersion: USHORT,
        },
        OperatingSystemVersion: ULONG,
    },
    ImageCharacteristics: USHORT,
    DllCharacteristics: USHORT,
    Machine: USHORT,
    ImageContainsCode: BOOLEAN,
    U2: extern union {
        ImageFlags: UCHAR,
        S: packed struct(UCHAR) {
            ComPlusNativeReady: u1,
            ComPlusILOnly: u1,
            ImageDynamicallyRelocated: u1,
            ImageMappedFlat: u1,
            BaseBelow4gb: u1,
            ComPlusPrefer32bit: u1,
            Reserved: u2,
        },
    },
    LoaderFlags: ULONG,
    ImageFileSize: ULONG,
    CheckSum: ULONG,
};

pub const RTL_USER_PROCESS_INFORMATION = extern struct {
    Length: ULONG,
    ProcessHandle: ?HANDLE,
    ThreadHandle: ?HANDLE,
    ClientId: CLIENT_ID,
    ImageInformation: SECTION_IMAGE_INFORMATION,
};

pub const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED = 0x00000001;
pub const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = 0x00000002;
pub const RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE = 0x00000004; // don't update synchronization objects

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD,
    lpSecurityDescriptor: ?LPVOID,
    bInheritHandle: BOOL,
};
pub const LPSECURITY_ATTRIBUTES = *SECURITY_ATTRIBUTES;

pub const AF = struct {
    pub const UNSPEC = 0;
    pub const UNIX = 1;
    pub const INET = 2;
    pub const IMPLINK = 3;
    pub const PUP = 4;
    pub const CHAOS = 5;
    pub const NS = 6;
    pub const IPX = 6;
    pub const ISO = 7;
    pub const ECMA = 8;
    pub const DATAKIT = 9;
    pub const CCITT = 10;
    pub const SNA = 11;
    pub const DECnet = 12;
    pub const DLI = 13;
    pub const LAT = 14;
    pub const HYLINK = 15;
    pub const APPLETALK = 16;
    pub const NETBIOS = 17;
    pub const VOICEVIEW = 18;
    pub const FIREFOX = 19;
    pub const UNKNOWN1 = 20;
    pub const BAN = 21;
    pub const ATM = 22;
    pub const INET6 = 23;
    pub const CLUSTER = 24;
    pub const @"12844" = 25;
    pub const IRDA = 26;
    pub const NETDES = 28;
    pub const MAX = 29;
    pub const TCNPROCESS = 29;
    pub const TCNMESSAGE = 30;
    pub const ICLFXBM = 31;
    pub const LINK = 33;
    pub const HYPERV = 34;
};

pub const SOCK = struct {
    pub const STREAM = 1;
    pub const DGRAM = 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;
};

pub const COINIT_MULTITHREADED = 0x0;
pub const COINIT_APARTMENTTHREADED = 0x2;
pub const COINIT_DISABLE_OLE1DDE = 0x4;
pub const COINIT_SPEED_OVER_MEMORY = 0x8;

pub const DLL_PROCESS_ATTACH = 1;
pub const DLL_PROCESS_DETACH = 0;

pub const PSECURITY_DESCRIPTOR = *anyopaque;
pub const PSECURITY_QUALITY_OF_SERVICE = *anyopaque;

pub const CREATE_SUSPENDED = 0x4;

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: ?PCUNICODE_STRING,
    Attributes: ULONG,
    SecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    SecurityQualityOfService: ?PSECURITY_QUALITY_OF_SERVICE,
};
pub const POBJECT_ATTRIBUTES = *OBJECT_ATTRIBUTES;
pub const PCOBJECT_ATTRIBUTES = *const OBJECT_ATTRIBUTES;

pub const JOBOBJECTINFOCLASS = enum(c_int) {
    JobObjectBasicAccountingInformation = 1,                  // q: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
    JobObjectBasicLimitInformation,                           // qs: JOBOBJECT_BASIC_LIMIT_INFORMATION
    JobObjectBasicProcessIdList,                              // q: JOBOBJECT_BASIC_PROCESS_ID_LIST
    JobObjectBasicUIRestrictions,                             // qs: JOBOBJECT_BASIC_UI_RESTRICTIONS
    JobObjectSecurityLimitInformation,                        // qs: JOBOBJECT_SECURITY_LIMIT_INFORMATION
    JobObjectEndOfJobTimeInformation,                         // qs: JOBOBJECT_END_OF_JOB_TIME_INFORMATION
    JobObjectAssociateCompletionPortInformation,              // s: JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    JobObjectBasicAndIoAccountingInformation,                 // q: JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION
    JobObjectExtendedLimitInformation,                        // qs: JOBOBJECT_EXTENDED_LIMIT_INFORMATION[V2]
    JobObjectJobSetInformation,                               // q: JOBOBJECT_JOBSET_INFORMATION
    JobObjectGroupInformation,                                // q: USHORT
    JobObjectNotificationLimitInformation,                    // q: JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION
    JobObjectLimitViolationInformation,                       // q: JOBOBJECT_LIMIT_VIOLATION_INFORMATION
    JobObjectGroupInformationEx,                              // qs: GROUP_AFFINITY (ARRAY)
    JobObjectCpuRateControlInformation,                       // qs: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    JobObjectCompletionFilter,                                // qs: ULONG
    JobObjectCompletionCounter,                               // qs: ULONG
    JobObjectFreezeInformation,                               // qs: JOBOBJECT_FREEZE_INFORMATION
    JobObjectExtendedAccountingInformation,                   // qs: JOBOBJECT_EXTENDED_ACCOUNTING_INFORMATION
    JobObjectWakeInformation,                                 // qs: JOBOBJECT_WAKE_INFORMATION
    JobObjectBackgroundInformation,                           // s: BOOLEAN
    JobObjectSchedulingRankBiasInformation,                   // s: JOBOBJECT_SCHEDULING_RANK_BIAS_INFORMATION
    JobObjectTimerVirtualizationInformation,                  // s: JOBOBJECT_TIMER_VIRTUALIZATION_INFORMATION
    JobObjectCycleTimeNotification,                           // s: JOBOBJECT_CYCLE_TIME_NOTIFICATION
    JobObjectClearEvent,                                      // s: HANDLE
    JobObjectInterferenceInformation,                         // q: JOBOBJECT_INTERFERENCE_INFORMATION
    JobObjectClearPeakJobMemoryUsed,                          // s: NULL
    JobObjectMemoryUsageInformation,                          // q: JOBOBJECT_MEMORY_USAGE_INFORMATION // JOBOBJECT_MEMORY_USAGE_INFORMATION_V2
    JobObjectSharedCommit,                                    // q: JOBOBJECT_SHARED_COMMIT
    JobObjectContainerId,                                     // q: JOBOBJECT_CONTAINER_IDENTIFIER_V2
    JobObjectIoRateControlInformation,                        // qs: JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE, JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V2, JOBOBJECT_IO_RATE_CONTROL_INFORMATION_NATIVE_V3
    JobObjectNetRateControlInformation,                       // qs: JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    JobObjectNotificationLimitInformation2,                   // qs: JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION_2
    JobObjectLimitViolationInformation2,                      // qs: JOBOBJECT_LIMIT_VIOLATION_INFORMATION_2
    JobObjectCreateSilo,                                      // s: NULL
    JobObjectSiloBasicInformation,                            // q: SILOOBJECT_BASIC_INFORMATION
    JobObjectSiloRootDirectory,                               // q: SILOOBJECT_ROOT_DIRECTORY
    JobObjectServerSiloBasicInformation,                      // q: SERVERSILO_BASIC_INFORMATION
    JobObjectServerSiloUserSharedData,                        // q: SILO_USER_SHARED_DATA // NtQueryInformationJobObject(NULL, 39, Buffer, sizeof(SILO_USER_SHARED_DATA), 0);
    JobObjectServerSiloInitialize,                            // qs: SERVERSILO_INIT_INFORMATION
    JobObjectServerSiloRunningState,                          // s: BOOLEAN
    JobObjectIoAttribution,                                   // q: JOBOBJECT_IO_ATTRIBUTION_INFORMATION
    JobObjectMemoryPartitionInformation,                      // qs: JOBOBJECT_MEMORY_PARTITION_INFORMATION
    JobObjectContainerTelemetryId,                            // s: GUID // NtSetInformationJobObject(_In_ PGUID, 44, _In_ PGUID, sizeof(GUID)); // daxexec
    JobObjectSiloSystemRoot,                                  // s: UNICODE_STRING
    JobObjectEnergyTrackingState,                             // q: JOBOBJECT_ENERGY_TRACKING_STATE
    JobObjectThreadImpersonationInformation,                  // qs: BOOLEAN
    JobObjectIoPriorityLimit,                                 // qs: JOBOBJECT_IO_PRIORITY_LIMIT
    JobObjectPagePriorityLimit,                               // qs: JOBOBJECT_PAGE_PRIORITY_LIMIT
    JobObjectServerSiloDiagnosticInformation,                 // q: SERVERSILO_DIAGNOSTIC_INFORMATION // since 24H2
    JobObjectNetworkAccountingInformation,                    // q: JOBOBJECT_NETWORK_ACCOUNTING_INFORMATION
    JobObjectCpuPartition,                                    // qs: JOBOBJECT_CPU_PARTITION_INFORMATION // since 25H2
    MaxJobObjectInfoClass,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: ULONGLONG,
    WriteOperationCount: ULONGLONG,
    OtherOperationCount: ULONGLONG,
    ReadTransferCount: ULONGLONG,
    WriteTransferCount: ULONGLONG,
    OtherTransferCount: ULONGLONG,
};

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: LARGE_INTEGER,
    PerJobUserTimeLimit: LARGE_INTEGER,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: SIZE_T,
    MaximumWorkingSetSize: SIZE_T,
    ActiveProcessLimit: DWORD,
    Affinity: ULONG_PTR,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: SIZE_T,
    JobMemoryLimit: SIZE_T,
    PeakProcessMemoryUsed: SIZE_T,
    PeakJobMemoryUsed: SIZE_T,
};

pub const JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
pub const JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

pub const WAIT_OBJECT_0 = 0;

pub const PS_CREATE_STATE = enum(u32) {
    InitialState,
    FailOnFileOpen,
    FailOnSectionCreate,
    FailExeFormat,
    FailMachineMismatch,
    FailExeName, // Debugger specified
    Success,
    MaximumStates,
};

pub const PPS_CREATE_INFO = *PS_CREATE_INFO;
pub const PS_CREATE_INFO = extern struct {
    Size: SIZE_T,
    State: PS_CREATE_STATE,
    U: extern union {
        InitialState: extern struct {
            U: extern union {
                InitFlags: ULONG,
                S: packed struct(ULONG) {
                    WriteOutputOnExit: u1,
                    DetectManifest: u1,
                    IFEOSkipDebugger: u1,
                    IFEODoNotPropagateKeyState: u1,
                    SpareBits1: u4,
                    SpareBits2: u8,
                    ProhibitedImageCharacteristics: u16,
                },
            },
        },
        FailSection: extern struct {
            FileHandle: HANDLE,
        },
        ExeFormat: extern struct {
            DllCharacteristics: USHORT,
        },
        ExeName: extern struct {
            IFEOKey: HANDLE,
        },
        SuccessState: extern struct {
            U: extern union {
                OutputFlags: ULONG,
                S: packed struct(ULONG) {
                    ProtectedProcess: u1,
                    AddressSpaceOverride: u1,
                    DevOverrideEnabled: u1, // from Image File Execution Options
                    ManifestDetected: u1,
                    ProtectedProcessLight: u1,
                    SpareBits1: u3,
                    SpareBits2: u8,
                    SpareBits3: u16,
                },
            },
            FileHandle: HANDLE,
            SectionHandle: HANDLE,
            UserProcessParametersNative: ULONGLONG,
            UserProcessParametersWow64: ULONG,
            CurrentParameterFlags: ULONG,
            PebAddressNative: ULONGLONG,
            PebAddressWow64: ULONG,
            ManifestAddress: ULONGLONG,
            ManifestSize: ULONG,
        },
    },
};

pub const MB_ICONEXCLAMATION = 0x00000030;
pub const MB_ICONASTERISK = 0x00000040;
pub const MB_SYSTEMMODAL = 0x00001000;

pub const IMAGE_DOS_HEADER = extern struct {
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

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
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

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
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

pub const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 8) IMAGE_NT_HEADERS64 else IMAGE_NT_HEADERS32;

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
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

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    Misc: extern union {
        PhysicalAddress: u32,
        VirtualSize: u32,
    },
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const _SID_IDENTIFIER_AUTHORITY = extern struct {
    Value: [6]UCHAR = @import("std").mem.zeroes([6]u8),
};
pub const SID_IDENTIFIER_AUTHORITY = _SID_IDENTIFIER_AUTHORITY;
pub const PSID_IDENTIFIER_AUTHORITY = [*c]_SID_IDENTIFIER_AUTHORITY;

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: PSID,
};

comptime {
    std.debug.assert(@offsetOf(IMAGE_DOS_HEADER, "e_lfanew") == 60);
    std.debug.assert(@offsetOf(IMAGE_NT_HEADERS, "OptionalHeader") == 24);
    std.debug.assert(@offsetOf(IMAGE_EXPORT_DIRECTORY, "NumberOfFunctions") == 20);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "Misc") == 8);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "SizeOfRawData") == 16);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "PointerToLinenumbers") == 28);
    std.debug.assert(@offsetOf(IMAGE_SECTION_HEADER, "Characteristics") == 36);
}

pub const IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

pub const EXTENDED_NAME_FORMAT = enum(u32) {
    NameUnknown = 0,
    NameFullyQualifiedDN = 1,
    NameSamCompatible = 2,
    NameDisplay = 3,
    NameUniqueId = 6,
    NameCanonical = 7,
    NameUserPrincipal = 8,
    NameCanonicalEx = 9,
    NameServicePrincipal = 10,
    NameDnsDomain = 12,
    NameGivenName = 13,
    NameSurname = 14
};

const section_name = ".winapi";

//
// KERNEL32 function types
//
pub fn VirtualAlloc(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) linksection(section_name) callconv(.winapi) ?LPVOID {
    const f = def(*const @TypeOf(VirtualAlloc), "VirtualAlloc", "kernel32");
    return f(lpAddress, dwSize, flAllocationType, flProtect);
}

pub fn VirtualQuery(
    lpAddress: ?LPVOID,
    lpBuffer: *MEMORY_BASIC_INFORMATION,
    dwLength: SIZE_T,
) linksection(section_name) callconv(.winapi) SIZE_T {
    const f = def(*const @TypeOf(VirtualQuery), "VirtualQuery", "kernel32");
    return f(lpAddress, lpBuffer, dwLength);
}

pub fn VirtualProtect(
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualProtect), "VirtualProtect", "kernel32");
    return f(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

pub fn VirtualFree(
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualFree), "VirtualFree", "kernel32");
    return f(lpAddress, dwSize, dwFreeType);
}

pub fn GetLastError() linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetLastError), "GetLastError", "kernel32");
    return f();
}

pub fn SetLastError(dwErrCode: DWORD) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(SetLastError), "SetLastError", "kernel32");
    f(dwErrCode);
}

pub fn Sleep(dwMilliseconds: DWORD) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(Sleep), "Sleep", "kernel32");
    f(dwMilliseconds);
}

pub fn ExitProcess(uExitCode: UINT) linksection(section_name) callconv(.winapi) noreturn {
    const f = def(*const @TypeOf(ExitProcess), "ExitProcess", "kernel32");
    f(uExitCode);
}

pub fn GetCurrentProcess() linksection(section_name) callconv(.winapi) HANDLE {
    const f = def(*const @TypeOf(GetCurrentProcess), "GetCurrentProcess", "kernel32");
    return f();
}

pub fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD
) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(WaitForSingleObject), "WaitForSingleObject", "kernel32");
    return f(hHandle, dwMilliseconds);
}

pub fn ReadFile(
    hFile: HANDLE,
    lpBuffer: LPVOID,
    nNumberOfBytesToRead: DWORD,
    lpNumberOfBytesRead: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(ReadFile), "ReadFile", "kernel32");
    return f(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

pub fn WriteFile(
    hFile: HANDLE,
    lpBuffer: LPCVOID,
    nNumberOfBytesToWrite: DWORD,
    lpNumberOfBytesWritten: ?*DWORD,
    lpOverlapped: ?*OVERLAPPED,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(WriteFile), "WriteFile", "kernel32");
    return f(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

pub fn DuplicateHandle(
    hSourceProcessHandle: HANDLE,
    hSourceHandle: HANDLE,
    hTargetProcessHandle: HANDLE,
    lpTargetHandle: *HANDLE,
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwOptions: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(DuplicateHandle), "DuplicateHandle", "kernel32");
    return f(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}

pub fn GetCurrentThreadId() linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetCurrentThreadId), "GetCurrentThreadId", "kernel32");
    return f();
}

pub fn FreeLibrary(hModule: HMODULE) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(FreeLibrary), "FreeLibrary", "kernel32");
    return f(hModule);
}

pub fn CreateThread(
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(CreateThread), "CreateThread", "kernel32");
    return f(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

pub fn GetSystemInfo(lpSystemInfo: *SYSTEM_INFO) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(GetSystemInfo), "GetSystemInfo", "kernel32");
    f(lpSystemInfo);
}

pub fn VirtualFreeEx(
    hProcess: HANDLE,
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    dwFreeType: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualFreeEx), "VirtualFreeEx", "kernel32");
    return f(hProcess, lpAddress, dwSize, dwFreeType);
}

pub fn GetModuleFileNameA(
    hModule: ?HMODULE,
    lpFilename: LPSTR,
    nSize: DWORD,
) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetModuleFileNameA), "GetModuleFileNameA", "kernel32");
    return f(hModule, lpFilename, nSize);
}

pub fn GetCurrentProcessId() linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetCurrentProcessId), "GetCurrentProcessId", "kernel32");
    return f();
}

pub fn GetProcessId(hProcess: HANDLE) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetProcessId), "GetProcessId", "kernel32");
    return f(hProcess);
}

pub fn GetCurrentThread() linksection(section_name) callconv(.winapi) HANDLE {
    const f = def(*const @TypeOf(GetCurrentThread), "GetCurrentThread", "kernel32");
    return f();
}

pub fn CloseHandle(hObject: HANDLE) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(CloseHandle), "CloseHandle", "kernel32");
    return f(hObject);
}

pub fn FlushInstructionCache(
    hProcess: HANDLE,
    lpBaseAddress: ?LPCVOID,
    dwSize: SIZE_T,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(FlushInstructionCache), "FlushInstructionCache", "kernel32");
    return f(hProcess, lpBaseAddress, dwSize);
}

pub fn FreeConsole() linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(FreeConsole), "FreeConsole", "kernel32");
    return f();
}

pub fn AttachConsole(dwProcessId: DWORD) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(AttachConsole), "AttachConsole", "kernel32");
    return f(dwProcessId);
}

pub fn IsWow64Process(
    hProcess: HANDLE,
    Wow64Process: *BOOL,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(IsWow64Process), "IsWow64Process", "kernel32");
    return f(hProcess, Wow64Process);
}

pub fn GetExitCodeProcess(
    hProcess: HANDLE,
    lpExitCode: *DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(GetExitCodeProcess), "GetExitCodeProcess", "kernel32");
    return f(hProcess, lpExitCode);
}

pub fn GetModuleHandleA(lpModuleName: ?LPCSTR) linksection(section_name) callconv(.winapi) ?HMODULE {
    const f = def(*const @TypeOf(GetModuleHandleA), "GetModuleHandleA", "kernel32");
    return f(lpModuleName);
}

pub fn LoadLibraryA(lpLibFileName: LPCSTR) linksection(section_name) callconv(.winapi) ?HMODULE {
    const f = def(*const @TypeOf(LoadLibraryA), "LoadLibraryA", "kernel32");
    return f(lpLibFileName);
}

pub fn GetProcAddress(
    hModule: HMODULE,
    lpProcName: LPCSTR,
) linksection(section_name) callconv(.winapi) ?FARPROC {
    const f = def(*const @TypeOf(GetProcAddress), "GetProcAddress", "kernel32");
    return f(hModule, lpProcName);
}

pub fn CreatePipe(
    hReadPipe: *HANDLE,
    hWritePipe: *HANDLE,
    lpPipeAttributes: ?*SECURITY_ATTRIBUTES,
    nSize: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(CreatePipe), "CreatePipe", "kernel32");
    return f(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
}

pub fn ResumeThread(hThread: HANDLE) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(ResumeThread), "ResumeThread", "kernel32");
    return f(hThread);
}

pub fn SuspendThread(hThread: HANDLE) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(SuspendThread), "SuspendThread", "kernel32");
    return f(hThread);
}

pub fn VirtualAllocEx(
    hProcess: HANDLE,
    lpAddress: ?LPVOID,
    dwSize: SIZE_T,
    flAllocationType: DWORD,
    flProtect: DWORD,
) linksection(section_name) callconv(.winapi) ?LPVOID {
    const f = def(*const @TypeOf(VirtualAllocEx), "VirtualAllocEx", "kernel32");
    return f(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

pub fn VirtualProtectEx(
    hProcess: HANDLE,
    lpAddress: LPVOID,
    dwSize: SIZE_T,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(VirtualProtectEx), "VirtualProtectEx", "kernel32");
    return f(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

pub fn CreateFileMappingA(
    hFile: HANDLE,
    lpFileMappingAttributes: ?*SECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: ?LPCSTR,
) linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(CreateFileMappingA), "CreateFileMappingA", "kernel32");
    return f(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

pub fn GetThreadContext(
    hThread: HANDLE,
    lpContext: *CONTEXT,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(GetThreadContext), "GetThreadContext", "kernel32");
    return f(hThread, lpContext);
}

pub fn GetThreadId(hThread: HANDLE) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetThreadId), "GetThreadId", "kernel32");
    return f(hThread);
}

pub fn SetThreadContext(
    hThread: HANDLE,
    lpContext: *const CONTEXT,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(SetThreadContext), "SetThreadContext", "kernel32");
    return f(hThread, lpContext);
}

pub fn MapViewOfFile(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
) linksection(section_name) callconv(.winapi) LPVOID {
    const f = def(*const @TypeOf(MapViewOfFile), "MapViewOfFile", "kernel32");
    return f(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
}

pub fn UnmapViewOfFile(lpBaseAddress: LPCVOID) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(UnmapViewOfFile), "UnmapViewOfFile", "kernel32");
    return f(lpBaseAddress);
}

pub fn OpenProcess(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwProcessId: DWORD,
) linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(OpenProcess), "OpenProcess", "kernel32");
    return f(dwDesiredAccess, bInheritHandle, dwProcessId);
}

pub fn OpenThread(
    dwDesiredAccess: DWORD,
    bInheritHandle: BOOL,
    dwThreadId: DWORD,
) linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(OpenThread), "OpenThread", "kernel32");
    return f(dwDesiredAccess, bInheritHandle, dwThreadId);
}

pub fn WriteProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPVOID,
    lpBuffer: LPCVOID,
    nSize: SIZE_T,
    lpNumberOfBytesWritten: ?*SIZE_T,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(WriteProcessMemory), "WriteProcessMemory", "kernel32");
    return f(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

pub fn ReadProcessMemory(
    hProcess: HANDLE,
    lpBaseAddress: LPCVOID,
    lpBuffer: LPVOID,
    nSize: SIZE_T,
    lpNumberOfBytesRead: ?*SIZE_T,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(ReadProcessMemory), "ReadProcessMemory", "kernel32");
    return f(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

pub fn CreateRemoteThread(
    hProcess: HANDLE,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    dwStackSize: SIZE_T,
    lpStartAddress: LPTHREAD_START_ROUTINE,
    lpParameter: ?LPVOID,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(CreateRemoteThread), "CreateRemoteThread", "kernel32");
    return f(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

pub fn GetCurrentDirectoryW(
    nBufferLength: DWORD,
    lpBuffer: ?[*]WCHAR,
) linksection(section_name) callconv(.winapi) DWORD {
    const f = def(*const @TypeOf(GetCurrentDirectoryW), "GetCurrentDirectoryW", "kernel32");
    return f(nBufferLength, lpBuffer);
}

pub fn HeapAlloc(
    hHeap: ?HANDLE,
    dwFlags: DWORD,
    dwBytes: SIZE_T,
) linksection(section_name) callconv(.winapi) ?LPVOID {
    const f = def(*const @TypeOf(HeapAlloc), "HeapAlloc", "kernel32");
    return f(hHeap, dwFlags, dwBytes);
}

pub fn HeapFree(
    hHeap: ?HANDLE,
    dwFlags: DWORD,
    lpMem: ?LPVOID,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(HeapFree), "HeapFree", "kernel32");
    return f(hHeap, dwFlags, lpMem);
}

pub fn GetProcessHeap() linksection(section_name) callconv(.winapi) ?HANDLE {
    const f = def(*const @TypeOf(GetProcessHeap), "GetProcessHeap", "kernel32");
    return f();
}

pub fn OutputDebugStringA(lpOutputString: ?LPCSTR) linksection(section_name) callconv(.winapi) void {
    const f = def(*const @TypeOf(OutputDebugStringA), "OutputDebugStringA", "kernel32");
    f(lpOutputString);
}

pub fn GetFileSizeEx(
    hFile: HANDLE,
    lpFileSize: *LARGE_INTEGER,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(GetFileSizeEx), "GetFileSizeEx", "kernel32");
    return f(hFile, lpFileSize);
}

pub fn SetFilePointerEx(
    hFile: HANDLE,
    liDistanceToMove: LARGE_INTEGER,
    lpNewFilePointer: ?*LARGE_INTEGER,
    dwMoveMethod: DWORD,
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(SetFilePointerEx), "SetFilePointerEx", "kernel32");
    return f(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
}

pub fn LocalFree(hMem: HLOCAL) linksection(section_name) callconv(.winapi) ?HLOCAL {
    const f = def(*const @TypeOf(LocalFree), "LocalFree", "kernel32");
    return f(hMem);
}

pub const LPPROCESS_INFORMATION = *PROCESS_INFORMATION;
pub const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};

pub const LPSTARTUPINFOW = *STARTUPINFOW;
pub const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?LPWSTR,
    lpDesktop: ?LPWSTR,
    lpTitle: ?LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: WORD,
    cbReserved2: WORD,
    lpReserved2: ?LPBYTE,
    hStdInput: ?HANDLE,
    hStdOutput: ?HANDLE,
    hStdError: ?HANDLE,
};

pub fn CreateProcessW(
    lpApplicationName: ?LPCWSTR, // _In_opt_
    lpCommandLine: ?LPWSTR, // _Inout_opt_
    lpProcessAttributes: ?LPSECURITY_ATTRIBUTES, // _In_opt_
    lpThreadAttributes: ?LPSECURITY_ATTRIBUTES, // _In_opt_
    bInheritHandles: BOOL, // _In_
    dwCreationFlags: DWORD, // _In_
    lpEnvironment: ?LPVOID, // _In_opt_
    lpCurrentDirectory: ?LPCWSTR, // _In_opt_
    lpStartupInfo: LPSTARTUPINFOW, // _In_
    lpProcessInformation: LPPROCESS_INFORMATION, // _Out_
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(CreateProcessW), "CreateProcessW", "kernel32");
    return f(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

//
// NTDLL function types
//
pub const PFN_RtlCloneUserProcess = *const fn (
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    DebugPort: ?HANDLE,
    ProcessInformation: *RTL_USER_PROCESS_INFORMATION,
) callconv(.winapi) NTSTATUS;

pub fn RtlGetVersion(
    lpVersionInformation: *RTL_OSVERSIONINFOW,
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlGetVersion), "RtlGetVersion", "ntdll");
    return f(lpVersionInformation);
}

pub const PFN_NtSuspendThread = *const fn (
    ThreadHandle: HANDLE,
    PreviousSuspendCount: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateThread = *const fn (
    ThreadHandle: ?HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub fn NtOpenProcess(
    ProcessHandle: *HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
    ClientId: ?*CLIENT_ID,
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtOpenProcess), "NtOpenProcess", "ntdll");
    return f(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

pub const PFN_NtResumeProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtSuspendProcess = *const fn (ProcessHandle: HANDLE) callconv(.winapi) NTSTATUS;

pub const PFN_NtCreateJobObject = *const fn (
    JobHandle: *HANDLE,
    DesiredAccess: DWORD,
    ObjectAttributes: ?*OBJECT_ATTRIBUTES,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtAssignProcessToJobObject = *const fn (
    JobHandle: HANDLE,
    ProcessHandle: HANDLE,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtTerminateJobObject = *const fn (
    JobHandle: HANDLE,
    ExitStatus: NTSTATUS,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtIsProcessInJob = *const fn (
    ProcessHandle: HANDLE,
    JobHandle: ?HANDLE,
) callconv(.winapi) NTSTATUS;

pub const PFN_NtSetInformationJobObject = *const fn (
    JobHandle: HANDLE,
    JobObjectInformationClass: JOBOBJECTINFOCLASS,
    JobObjectInformation: PVOID,
    JobObjectInformationLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub fn RtlWow64EnableFsRedirection(Wow64FsEnableRedirection: BOOLEAN) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlWow64EnableFsRedirection), "RtlWow64EnableFsRedirection", "ntdll");
    return f(Wow64FsEnableRedirection);
}

pub const CURDIR = extern struct {
    DosPath: UNICODE_STRING,
    Handle: HANDLE,
};

pub const PRTL_USER_PROCESS_PARAMETERS = *RTL_USER_PROCESS_PARAMETERS;
pub const RTL_USER_PROCESS_PARAMETERS = extern struct {
    MaximumLength: ULONG,
    Length: ULONG,

    Flags: ULONG,
    DebugFlags: ULONG,

    ConsoleHandle: HANDLE,
    ConsoleFlags: ULONG,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,

    CurrentDirectory: CURDIR,
    DllPath: UNICODE_STRING,
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
    Environment: ?PVOID,

    StartingX: ULONG,
    StartingY: ULONG,
    CountX: ULONG,
    CountY: ULONG,
    CountCharsX: ULONG,
    CountCharsY: ULONG,
    FillAttribute: ULONG,

    WindowFlags: ULONG,
    ShowWindowFlags: ULONG,
    WindowTitle: UNICODE_STRING,
    Desktop: UNICODE_STRING,
    ShellInfo: UNICODE_STRING,
    RuntimeData: UNICODE_STRING,
    CurrentDirectories: [32]RTL_DRIVE_LETTER_CURDIR,

    EnvironmentSize: ULONG_PTR,
    EnvironmentVersion: ULONG_PTR,

    PackageDependencyData: ?PVOID,
    ProcessGroupId: ULONG,
    LoaderThreads: ULONG, // THRESHOLD

    RedirectionDllName: UNICODE_STRING, // REDSTONE5
    HeapPartitionName: UNICODE_STRING, // 19H1
    DefaultThreadpoolCpuSetMasks: PULONGLONG,
    DefaultThreadpoolCpuSetMaskCount: ULONG,
    DefaultThreadpoolThreadMaximum: ULONG, // 20H1
    HeapMemoryTypeMask: ULONG, // WIN11 22H2
};

pub const RTL_DRIVE_LETTER_CURDIR = extern struct {
    Flags: c_ushort,
    Length: c_ushort,
    TimeStamp: ULONG,
    DosPath: UNICODE_STRING,
};

pub const PS_ATTRIBUTE = extern struct {
    Attribute: ULONG_PTR,
    Size: SIZE_T,
    u: extern union {
        Value: ULONG_PTR,
        ValuePtr: ?PVOID,
    },
    ReturnLength: ?PSIZE_T,
};

pub const PPS_ATTRIBUTE_LIST = *PS_ATTRIBUTE_LIST;
pub const PS_ATTRIBUTE_LIST = extern struct {
    TotalLength: SIZE_T,
    Attributes: [*]PS_ATTRIBUTE,
};

pub fn NtCreateUserProcess(
    ProcessHandle: PHANDLE, // _Out_
    ThreadHandle: PHANDLE, // _Out_
    ProcessDesiredAccess: ACCESS_MASK, // _In_
    ThreadDesiredAccess: ACCESS_MASK, // _In_
    ProcessObjectAttributes: ?PCOBJECT_ATTRIBUTES, // _In_opt_
    ThreadObjectAttributes: ?PCOBJECT_ATTRIBUTES, // _In_opt_
    ProcessFlags: ULONG, // _In_ (PROCESS_CREATE_FLAGS_*)
    ThreadFlags: ULONG, // _In_ (THREAD_CREATE_FLAGS_*)
    ProcessParameters: ?PRTL_USER_PROCESS_PARAMETERS, // _In_opt_
    CreateInfo: PPS_CREATE_INFO, // _Inout_
    AttributeList: ?PPS_ATTRIBUTE_LIST, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCreateUserProcess), "NtCreateUserProcess", "ntdll");
    return f(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

pub fn LdrLoadDll(
    DllPath: ?PCWSTR, // _In_opt_
    DllCharacteristics: ?PULONG, // _In_opt_
    DllName: PCUNICODE_STRING, // _In_
    DllHandle: *PVOID, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(LdrLoadDll), "LdrLoadDll", "ntdll");
    return f(DllPath, DllCharacteristics, DllName, DllHandle);
}

pub fn LdrUnloadDll(
    DllHandle: PVOID, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(LdrUnloadDll), "LdrUnloadDll", "ntdll");
    return f(DllHandle);
}

pub fn LdrGetProcedureAddress(
    DllHandle: PVOID, // _In_
    ProcedureName: ?PCANSI_STRING, // _In_opt_
    ProcedureNumber: ULONG, // _In_opt_
    ProcedureAddress: *PVOID, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(LdrGetProcedureAddress), "LdrGetProcedureAddress", "ntdll");
    return f(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress);
}

pub fn LdrGetProcedureAddressEx(
    DllHandle: PVOID, // _In_
    ProcedureName: ?PCANSI_STRING, // _In_opt_
    ProcedureNumber: ULONG, // _In_opt_
    ProcedureAddress: *PVOID, // _Out_
    Flags: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(LdrGetProcedureAddressEx), "LdrGetProcedureAddressEx", "ntdll");
    return f(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress, Flags);
}

pub fn LdrGetProcedureAddressForCaller(
    DllHandle: PVOID, // _In_
    ProcedureName: ?PCANSI_STRING, // _In_opt_
    ProcedureNumber: ULONG, // _In_opt_
    ProcedureAddress: *PVOID, // _Out_
    Flags: ULONG, // _In_
    CallerAddress: PVOID, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(LdrGetProcedureAddressForCaller), "LdrGetProcedureAddressForCaller", "ntdll");
    return f(DllHandle, ProcedureName, ProcedureNumber, ProcedureAddress, Flags, CallerAddress);
}

pub fn NtCreateFile(
    FileHandle: PHANDLE, // _Out_
    DesiredAccess: ACCESS_MASK, // _In_
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    AllocationSize: ?PLARGE_INTEGER, // _In_opt_
    FileAttributes: ULONG, // _In_
    ShareAccess: ULONG, // _In_
    CreateDisposition: ULONG, // _In_
    CreateOptions: ULONG, // _In_
    EaBuffer: ?PVOID, // _In_reads_bytes_opt_(EaLength)
    EaLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCreateFile), "NtCreateFile", "ntdll");
    return f(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

pub fn NtOpenFile(
    FileHandle: *HANDLE, // _Out_
    DesiredAccess: ACCESS_MASK, // _In_
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ShareAccess: ULONG, // _In_
    OpenOptions: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtOpenFile), "NtOpenFile", "ntdll");
    return f(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

pub fn NtFlushBuffersFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtFlushBuffersFile), "NtFlushBuffersFile", "ntdll");
    return f(FileHandle, IoStatusBlock);
}

pub fn NtDeviceIoControlFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    IoControlCode: ULONG, // _In_
    InputBuffer: ?PVOID, // _In_reads_bytes_opt_(InputBufferLength)
    InputBufferLength: ULONG, // _In_
    OutputBuffer: ?PVOID, // _Out_writes_bytes_opt_(OutputBufferLength)
    OutputBufferLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtDeviceIoControlFile), "NtDeviceIoControlFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

pub fn NtFsControlFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FsControlCode: ULONG, // _In_
    InputBuffer: ?PVOID, // _In_reads_bytes_opt_(InputBufferLength)
    InputBufferLength: ULONG, // _In_
    OutputBuffer: ?PVOID, // _Out_writes_bytes_opt_(OutputBufferLength)
    OutputBufferLength: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtFsControlFile), "NtFsControlFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

pub fn NtLockFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ByteOffset: PLARGE_INTEGER, // _In_
    Length: PLARGE_INTEGER, // _In_
    Key: ULONG, // _In_
    FailImmediately: BOOLEAN, // _In_
    ExclusiveLock: BOOLEAN, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtLockFile), "NtLockFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
}

pub fn NtUnlockFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ByteOffset: PLARGE_INTEGER, // _In_
    Length: PLARGE_INTEGER, // _In_
    Key: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtUnlockFile), "NtUnlockFile", "ntdll");
    return f(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
}

pub fn NtQueryDirectoryFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
    ReturnSingleEntry: BOOLEAN, // _In_
    FileName: ?PCUNICODE_STRING, // _In_opt_
    RestartScan: BOOLEAN, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryDirectoryFile), "NtQueryDirectoryFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}

pub fn RtlGetCurrentDirectory_U(
    BufferLength: ULONG, // _In_
    Buffer: [*]u16, // _Out_writes_bytes_(BufferLength)
) linksection(section_name) callconv(.winapi) ULONG {
    const f = def(*const @TypeOf(RtlGetCurrentDirectory_U), "RtlGetCurrentDirectory_U", "ntdll");
    return f(BufferLength, Buffer);
}

pub fn RtlSetCurrentDirectory_U(
    PathName: PCUNICODE_STRING, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlSetCurrentDirectory_U), "RtlSetCurrentDirectory_U", "ntdll");
    return f(PathName);
}

pub fn RtlQueryPerformanceCounter(
    PerformanceCounter: PLARGE_INTEGER, // _Out_
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(RtlQueryPerformanceCounter), "RtlQueryPerformanceCounter", "ntdll");
    return f(PerformanceCounter);
}

pub fn RtlQueryPerformanceFrequency(
    PerformanceFrequency: PLARGE_INTEGER, // _Out_
) linksection(section_name) callconv(.winapi) BOOL {
    const f = def(*const @TypeOf(RtlQueryPerformanceFrequency), "RtlQueryPerformanceFrequency", "ntdll");
    return f(PerformanceFrequency);
}

pub fn RtlGetSystemTimePrecise() linksection(section_name) callconv(.winapi) LARGE_INTEGER {
    const f = def(*const @TypeOf(RtlGetSystemTimePrecise), "RtlGetSystemTimePrecise", "ntdll");
    return f();
}

pub fn RtlGetFullPathName_U(
    FileName: PCWSTR, // _In_
    BufferLength: ULONG, // _In_
    Buffer: PWSTR, // _Out_writes_bytes_(BufferLength)
    ShortName: ?*PWSTR, // _Out_opt_
) linksection(section_name) callconv(.winapi) ULONG {
    const f = def(*const @TypeOf(RtlGetFullPathName_U), "RtlGetFullPathName_U", "ntdll");
    return f(FileName, BufferLength, Buffer, ShortName);
}

pub fn RtlEqualUnicodeString(
    String1: PCUNICODE_STRING, // _In_
    String2: PCUNICODE_STRING, // _In_
    CaseInSensitive: BOOLEAN, // _In_
) linksection(section_name) callconv(.winapi) BOOLEAN {
    const f = def(*const @TypeOf(RtlEqualUnicodeString), "RtlEqualUnicodeString", "ntdll");
    return f(String1, String2, CaseInSensitive);
}

pub fn RtlUpcaseUnicodeChar(
    SourceCharacter: u16, // _In_
) linksection(section_name) callconv(.winapi) u16 {
    const f = def(*const @TypeOf(RtlUpcaseUnicodeChar), "RtlUpcaseUnicodeChar", "ntdll");
    return f(SourceCharacter);
}

pub fn RtlReportSilentProcessExit(
    ProcessHandle: HANDLE, // _In_
    ExitStatus: NTSTATUS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlReportSilentProcessExit), "RtlReportSilentProcessExit", "ntdll");
    return f(ProcessHandle, ExitStatus);
}

pub fn RtlEnterCriticalSection(
    lpCriticalSection: PRTL_CRITICAL_SECTION, // _Inout_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlEnterCriticalSection), "RtlEnterCriticalSection", "ntdll");
    return f(lpCriticalSection);
}

pub fn RtlLeaveCriticalSection(
    lpCriticalSection: PRTL_CRITICAL_SECTION, // _Inout_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(RtlLeaveCriticalSection), "RtlLeaveCriticalSection", "ntdll");
    return f(lpCriticalSection);
}

pub fn NtClose(
    Handle: HANDLE, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtClose), "NtClose", "ntdll");
    return f(Handle);
}

pub fn NtTerminateProcess(
    ProcessHandle: ?HANDLE, // _In_opt_
    ExitStatus: NTSTATUS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtTerminateProcess), "NtTerminateProcess", "ntdll");
    return f(ProcessHandle, ExitStatus);
}

pub fn NtWaitForSingleObject(
    Handle: HANDLE, // _In_
    Alertable: BOOLEAN, // _In_
    Timeout: ?PLARGE_INTEGER, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtWaitForSingleObject), "NtWaitForSingleObject", "ntdll");
    return f(Handle, Alertable, Timeout);
}

pub fn NtWaitForAlertByThreadId(
    Address: ?PVOID, // _In_opt_
    Timeout: ?PLARGE_INTEGER, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtWaitForAlertByThreadId), "NtWaitForAlertByThreadId", "ntdll");
    return f(Address, Timeout);
}

pub fn NtQueryObject(
    Handle: ?HANDLE, // _In_opt_
    ObjectInformationClass: OBJECT_INFORMATION_CLASS, // _In_
    ObjectInformation: ?PVOID, // _Out_writes_bytes_opt_(ObjectInformationLength)
    ObjectInformationLength: ULONG, // _In_
    ReturnLength: ?PULONG, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryObject), "NtQueryObject", "ntdll");
    return f(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

pub fn NtQueryInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryInformationFile), "NtQueryInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

pub fn NtQueryVolumeInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FsInformation: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    FsInformationClass: FS_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryVolumeInformationFile), "NtQueryVolumeInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
}

pub fn NtQueryInformationProcess(
    ProcessHandle: HANDLE, // _In_
    ProcessInformationClass: PROCESSINFOCLASS, // _In_
    ProcessInformation: PVOID, // _Out_writes_bytes_(ThreadInformationLength)
    ProcessInformationLength: ULONG, // _In_
    ReturnLength: ?PULONG, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryInformationProcess), "NtQueryInformationProcess", "ntdll");
    return f(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

pub fn NtQueryInformationThread(
    ThreadHandle: HANDLE, // _In_
    ThreadInformationClass: THREADINFOCLASS, // _In_
    ThreadInformation: PVOID, // _Out_writes_bytes_(ThreadInformationLength)
    ThreadInformationLength: ULONG, // _In_
    ReturnLength: ?PULONG, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryInformationThread), "NtQueryInformationThread", "ntdll");
    return f(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}

pub const FILE_BASIC_INFORMATION = extern struct {
    CreationTime: LARGE_INTEGER,
    LastAccessTime: LARGE_INTEGER,
    LastWriteTime: LARGE_INTEGER,
    ChangeTime: LARGE_INTEGER,
    FileAttributes: ULONG,
};
pub const PFILE_BASIC_INFORMATION = *FILE_BASIC_INFORMATION;

pub fn NtQueryAttributesFile(
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    FileAttributes: PFILE_BASIC_INFORMATION, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQueryAttributesFile), "NtQueryAttributesFile", "ntdll");
    return f(ObjectAttributes, FileAttributes);
}

pub fn NtSetInformationFile(
    FileHandle: HANDLE, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    FileInformation: PVOID, // _In_reads_bytes_(Length)
    Length: ULONG, // _In_
    FileInformationClass: FILE_INFORMATION_CLASS, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtSetInformationFile), "NtSetInformationFile", "ntdll");
    return f(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

pub fn NtReadFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    Buffer: PVOID, // _Out_writes_bytes_(Length)
    Length: ULONG, // _In_
    ByteOffset: ?PLARGE_INTEGER, // _In_opt_
    Key: ?PULONG, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtReadFile), "NtReadFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

pub fn NtWriteFile(
    FileHandle: HANDLE, // _In_
    Event: ?HANDLE, // _In_opt_
    ApcRoutine: ?PIO_APC_ROUTINE, // _In_opt_
    ApcContext: ?PVOID, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    Buffer: PVOID, // _In_reads_bytes_(Length)
    Length: ULONG, // _In_
    ByteOffset: ?PLARGE_INTEGER, // _In_opt_
    Key: ?PULONG, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtWriteFile), "NtWriteFile", "ntdll");
    return f(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

pub fn NtCreateNamedPipeFile(
    FileHandle: *HANDLE, // _Out_
    DesiredAccess: ACCESS_MASK, // _In_
    ObjectAttributes: PCOBJECT_ATTRIBUTES, // _In_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
    ShareAccess: ULONG, // _In_
    CreateDisposition: ULONG, // _In_
    CreateOptions: ULONG, // _In_
    NamedPipeType: ULONG, // _In_
    ReadMode: ULONG, // _In_
    CompletionMode: ULONG, // _In_
    MaximumInstances: ULONG, // _In_
    InboundQuota: ULONG, // _In_
    OutboundQuota: ULONG, // _In_
    DefaultTimeout: ?PLARGE_INTEGER, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCreateNamedPipeFile), "NtCreateNamedPipeFile", "ntdll");
    return f(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
}

pub fn NtCreateSection(
    SectionHandle: PHANDLE, // _Out_
    DesiredAccess: ACCESS_MASK, // _In_
    ObjectAttributes: ?PCOBJECT_ATTRIBUTES, // _In_opt_
    MaximumSize: ?PLARGE_INTEGER, // _In_opt_
    SectionPageProtection: ULONG, // _In_
    AllocationAttributes: ULONG, // _In_
    FileHandle: ?HANDLE, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCreateSection), "NtCreateSection", "ntdll");
    return f(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

pub const SECTION_INHERIT = enum(c_int) {
    ViewShare = 1,
    ViewUnmap = 2,
};

pub fn NtMapViewOfSection(
    SectionHandle: HANDLE, // _In_
    ProcessHandle: HANDLE, // _In_
    BaseAddress: ?*PVOID, // _Inout_
    ZeroBits: ULONG_PTR, // _In_
    CommitSize: SIZE_T, // _In_
    SectionOffset: ?PLARGE_INTEGER, // _Inout_opt_
    ViewSize: PSIZE_T, // _Inout_
    InheritDispostion: SECTION_INHERIT, // _In_
    AllocationType: ULONG, // _In_
    PageProtection: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtMapViewOfSection), "NtMapViewOfSection", "ntdll");
    return f(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDispostion, AllocationType, PageProtection);
}

pub fn NtUnmapViewOfSection(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: ?PVOID, // _In_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtUnmapViewOfSection), "NtUnmapViewOfSection", "ntdll");
    return f(ProcessHandle, BaseAddress);
}

pub fn NtReadVirtualMemory(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: ?PVOID, // _In_opt_
    Buffer: PVOID, // _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead)
    NumberOfBytesToRead: SIZE_T, // _In_
    NumberOfBytesRead: ?PSIZE_T, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtReadVirtualMemory), "NtReadVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

pub fn NtWriteVirtualMemory(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: ?PVOID, // _In_opt_
    Buffer: PVOID, // _In_reads_bytes_(NumberOfBytesToWrite)
    NumberOfBytesToWrite: SIZE_T, // _In_
    NumberOfBytesWritten: ?PSIZE_T, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtWriteVirtualMemory), "NtWriteVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

pub fn NtProtectVirtualMemory(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: *PVOID, // _Inout_
    NumberOfBytesToProtect: PSIZE_T, // _Inout_
    NewAccessProtection: ULONG, // _In_
    OldAccessProtection: PULONG, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtProtectVirtualMemory), "NtProtectVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

pub fn NtDelayExecution(
    Alertable: BOOLEAN, // _In_
    DelayInterval: PLARGE_INTEGER, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtDelayExecution), "NtDelayExecution", "ntdll");
    return f(Alertable, DelayInterval);
}

pub fn NtQuerySystemInformation(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: ?PVOID, // _Out_writes_bytes_opt_(SystemInformationLength)
    SystemInformationLength: ULONG, // _In_
    ReturnLength: ?PULONG, // _Out_opt_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtQuerySystemInformation), "NtQuerySystemInformation", "ntdll");
    return f(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

pub fn NtCancelIoFileEx(
    FileHandle: HANDLE, // _In_
    IoRequestToCancel: ?PIO_STATUS_BLOCK, // _In_opt_
    IoStatusBlock: PIO_STATUS_BLOCK, // _Out_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtCancelIoFileEx), "NtCancelIoFileEx", "ntdll");
    return f(FileHandle, IoRequestToCancel, IoStatusBlock);
}

pub fn NtAllocateVirtualMemory(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: *PVOID, // _Inout_
    ZeroBits: ULONG_PTR, // _In_
    RegionSize: *SIZE_T, // _Inout_
    AllocationType: ULONG, // _In_
    Protect: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtAllocateVirtualMemory), "NtAllocateVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

pub fn NtFreeVirtualMemory(
    ProcessHandle: HANDLE, // _In_
    BaseAddress: *PVOID, // _Inout_
    RegionSize: *SIZE_T, // _Inout_
    FreeType: ULONG, // _In_
) linksection(section_name) callconv(.winapi) NTSTATUS {
    const f = def(*const @TypeOf(NtFreeVirtualMemory), "NtFreeVirtualMemory", "ntdll");
    return f(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

pub const PFN_NtCreateThreadEx = *const @TypeOf(std.os.windows.ntdll.NtCreateThreadEx);
pub const PFN_NtResumeThread = *const @TypeOf(std.os.windows.ntdll.NtResumeThread);

//
// ADVAPI32 function types
//
pub const PFN_OpenProcessToken = *const fn (
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *HANDLE,
) callconv(.winapi) BOOL;

pub const PFN_GetTokenInformation = *const fn (
    TokenHandle: HANDLE,
    TokenInformationClass: TOKEN_INFORMATION_CLASS,
    TokenInformation: ?*anyopaque,
    TokenInformationLength: DWORD,
    ReturnLength: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_CheckTokenMembership = *const fn (
    TokenHandle: ?HANDLE,
    SidToCheck: PSID,
    IsMember: PBOOL,
) callconv(.winapi) BOOL;

pub const PFN_AllocateAndInitializeSid = *const fn (
    pIdentifierAuthority: PSID_IDENTIFIER_AUTHORITY,
    nSubAuthorityCount: BYTE,
    nSubAuthority0: DWORD,
    nSubAuthority1: DWORD,
    nSubAuthority2: DWORD,
    nSubAuthority3: DWORD,
    nSubAuthority4: DWORD,
    nSubAuthority5: DWORD,
    nSubAuthority6: DWORD,
    nSubAuthority7: DWORD,
    pSid: *PSID,
) callconv(.winapi) BOOL;

pub const PFN_FreeSid = *const fn (
    pSid: PSID,
) callconv(.winapi) PVOID;

pub const PFN_ConvertSidToStringSidA = *const fn (
    pSid: PSID,
    pStringSid: *LPSTR,
) callconv(.winapi) BOOL;

pub const PFN_RtlGenRandom = *const fn (
    RandomBuffer: PVOID,
    RandomBufferLength: ULONG,
) callconv(.winapi) BOOL;

//
// USER32 function types
//
pub const PFN_MessageBoxA = *const fn (
    hWnd: ?HWND,
    lpText: ?LPCSTR,
    lpCaption: ?LPCSTR,
    uType: UINT,
) callconv(.winapi) i32;

pub const PFN_MessageBoxW = *const fn (
    hWnd: ?HWND,
    lpText: ?LPCWSTR,
    lpCaption: ?LPCWSTR,
    uType: UINT,
) callconv(.winapi) i32;

pub const PFN_EnumWindows = *const fn (
    lpEnumFunc: WNDENUMPROC,
    lParam: LPARAM,
) callconv(.winapi) BOOL;

pub const PFN_GetWindowThreadProcessId = *const fn (
    hWnd: HWND,
    lpdwProcessId: ?*DWORD,
) callconv(.winapi) DWORD;

pub const PFN_SetForegroundWindow = *const fn (hWnd: HWND) callconv(.winapi) BOOL;
pub const PFN_GetForegroundWindow = *const fn () callconv(.winapi) ?HWND;

//
// OLE32 function types
//
pub const PFN_CoInitializeEx = *const fn (
    pvReserved: ?LPVOID,
    dwCoInit: DWORD,
) callconv(.winapi) HRESULT;

pub const PFN_CoUninitialize = *const fn () callconv(.winapi) void;
pub const PFN_CoTaskMemAlloc = *const fn (size: SIZE_T) callconv(.winapi) ?LPVOID;
pub const PFN_CoTaskMemFree = *const fn (pv: LPVOID) callconv(.winapi) void;
pub const PFN_CoGetCurrentProcess = *const fn () callconv(.winapi) DWORD;
pub const PFN_CoGetCallerTID = *const fn (lpdwTID: *DWORD) callconv(.winapi) HRESULT;

//
// WS2_32 function types
//
pub const PFN_WSAStartup = *const fn (
    wVersionRequired: WORD,
    lpWSAData: *WSADATA,
) callconv(.winapi) i32;

pub const PFN_WSACleanup = *const fn () callconv(.winapi) i32;

pub const PFN_WSAGetLastError = *const fn () callconv(.winapi) WinsockError;

pub const PFN_WSASocketW = *const fn (
    af: i32,
    @"type": i32,
    protocol: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    g: u32,
    dwFlags: u32,
) callconv(.winapi) SOCKET;

pub const PFN_WSAPoll = *const fn (
    fdArray: [*]WSAPOLLFD,
    fds: u32,
    timeout: i32,
) callconv(.winapi) i32;

pub const PFN_WSAGetOverlappedResult = *const fn (
    s: SOCKET,
    lpOverlapped: *OVERLAPPED,
    lpcbTransfer: *DWORD,
    fWait: BOOL,
    lpdwFlags: *DWORD,
) callconv(.winapi) BOOL;

pub const PFN_WSASend = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSASendTo = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpTo: ?*const sockaddr,
    iToLen: i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSARecv = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBuffercount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_WSARecvFrom = *const fn (
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBuffercount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpFrom: ?*sockaddr,
    lpFromlen: ?*i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const PFN_closesocket = *const fn (s: SOCKET) callconv(.winapi) i32;

pub const PFN_getaddrinfo = *const fn (
    pNodeName: ?[*:0]const u8,
    pServiceName: ?[*:0]const u8,
    pHints: ?*const addrinfoa,
    ppResult: *?*addrinfoa,
) callconv(.winapi) i32;

pub const PFN_freeaddrinfo = *const fn (pAddrInfo: ?*addrinfoa) callconv(.winapi) void;

pub const PFN_bind = *const fn (
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub const PFN_connect = *const fn (
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub const PFN_ioctlsocket = *const fn (
    s: SOCKET,
    cmd: i32,
    argp: *u32,
) callconv(.winapi) i32;

pub const PFN_getsockopt = *const fn (
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: [*]u8,
    optlen: *i32,
) callconv(.winapi) i32;

pub const PFN_setsockopt = *const fn (
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: ?[*]const u8,
    optlen: i32,
) callconv(.winapi) i32;

//
// SECUR_32 function types
//
pub const PFN_GetUserNameExA = *const fn (
    NameFormat: EXTENDED_NAME_FORMAT,
    lpNameBuffer: ?LPSTR,
    nSize: *ULONG,
) callconv(.winapi) BOOLEAN;

//
// Define WIN32 function
//
const bof = @import("options").bof;

pub fn def(
    comptime T: type,
    comptime funcname: []const u8,
    comptime libname: []const u8,
) if (@import("options").define_functions) T else void {
    return if (@import("options").define_functions)
        @extern(T, .{
            .name = if (bof) libname ++ "$" ++ funcname else funcname,
            .is_dll_import = true, // __declspec(dllimport)
        })
    else {};
}

pub fn init() void {
    NtResumeThread = def(PFN_NtResumeThread, "NtResumeThread", "ntdll");
    NtSuspendThread = def(PFN_NtSuspendThread, "NtSuspendThread", "ntdll");
    NtTerminateThread = def(PFN_NtTerminateThread, "NtTerminateThread", "ntdll");
    NtResumeProcess = def(PFN_NtResumeProcess, "NtResumeProcess", "ntdll");
    NtSuspendProcess = def(PFN_NtSuspendProcess, "NtSuspendProcess", "ntdll");
    NtCreateJobObject = def(PFN_NtCreateJobObject, "NtCreateJobObject", "ntdll");
    NtAssignProcessToJobObject = def(PFN_NtAssignProcessToJobObject, "NtAssignProcessToJobObject", "ntdll");
    NtTerminateJobObject = def(PFN_NtTerminateJobObject, "NtTerminateJobObject", "ntdll");
    NtIsProcessInJob = def(PFN_NtIsProcessInJob, "NtIsProcessInJob", "ntdll");
    NtSetInformationJobObject = def(PFN_NtSetInformationJobObject, "NtSetInformationJobObject", "ntdll");
    NtCreateThreadEx = def(PFN_NtCreateThreadEx, "NtCreateThreadEx", "ntdll");
    RtlCloneUserProcess = def(PFN_RtlCloneUserProcess, "RtlCloneUserProcess", "ntdll");

    MessageBoxA = def(PFN_MessageBoxA, "MessageBoxA", "user32");
    MessageBoxW = def(PFN_MessageBoxW, "MessageBoxW", "user32");
    EnumWindows = def(PFN_EnumWindows, "EnumWindows", "user32");
    GetWindowThreadProcessId = def(PFN_GetWindowThreadProcessId, "GetWindowThreadProcessId", "user32");
    SetForegroundWindow = def(PFN_SetForegroundWindow, "SetForegroundWindow", "user32");
    GetForegroundWindow = def(PFN_GetForegroundWindow, "GetForegroundWindow", "user32");

    CoInitializeEx = def(PFN_CoInitializeEx, "CoInitializeEx", "ole32");
    CoUninitialize = def(PFN_CoUninitialize, "CoUninitialize", "ole32");
    CoTaskMemAlloc = def(PFN_CoTaskMemAlloc, "CoTaskMemAlloc", "ole32");
    CoTaskMemFree = def(PFN_CoTaskMemFree, "CoTaskMemFree", "ole32");
    CoGetCurrentProcess = def(PFN_CoGetCurrentProcess, "CoGetCurrentProcess", "ole32");
    CoGetCallerTID = def(PFN_CoGetCallerTID, "CoGetCallerTID", "ole32");

    OpenProcessToken = def(PFN_OpenProcessToken, "OpenProcessToken", "advapi32");
    GetTokenInformation = def(PFN_GetTokenInformation, "GetTokenInformation", "advapi32");
    CheckTokenMembership = def(PFN_CheckTokenMembership, "CheckTokenMembership", "advapi32");
    AllocateAndInitializeSid = def(PFN_AllocateAndInitializeSid, "AllocateAndInitializeSid", "advapi32");
    FreeSid = def(PFN_FreeSid, "FreeSid", "advapi32");
    ConvertSidToStringSidA = def(PFN_ConvertSidToStringSidA, "ConvertSidToStringSidA", "advapi32");
    RtlGenRandom = def(PFN_RtlGenRandom, "SystemFunction036", "advapi32");

    WSAStartup = def(PFN_WSAStartup, "WSAStartup", "ws2_32");
    WSACleanup = def(PFN_WSACleanup, "WSACleanup", "ws2_32");
    WSAGetLastError = def(PFN_WSAGetLastError, "WSAGetLastError", "ws2_32");
    WSASocketW = def(PFN_WSASocketW, "WSASocketW", "ws2_32");
    WSAPoll = def(PFN_WSAPoll, "WSAPoll", "ws2_32");
    WSAGetOverlappedResult = def(PFN_WSAGetOverlappedResult, "WSAGetOverlappedResult", "ws2_32");
    WSASend = def(PFN_WSASend, "WSASend", "ws2_32");
    WSASendTo = def(PFN_WSASendTo, "WSASendTo", "ws2_32");
    WSARecvFrom = def(PFN_WSARecvFrom, "WSARecvFrom", "ws2_32");
    closesocket = def(PFN_closesocket, "closesocket", "ws2_32");
    getaddrinfo = def(PFN_getaddrinfo, "getaddrinfo", "ws2_32");
    freeaddrinfo = def(PFN_freeaddrinfo, "freeaddrinfo", "ws2_32");
    bind = def(PFN_bind, "bind", "ws2_32");
    connect = def(PFN_connect, "connect", "ws2_32");
    ioctlsocket = def(PFN_ioctlsocket, "ioctlsocket", "ws2_32");
    getsockopt = def(PFN_getsockopt, "getsockopt", "ws2_32");
    setsockopt = def(PFN_setsockopt, "setsockopt", "ws2_32");

    GetUserNameExA = def(PFN_GetUserNameExA, "GetUserNameExA", "secur32");
}

//
// NTDLL function definitions
//
pub var NtResumeThread: PFN_NtResumeThread = undefined;
pub var NtSuspendThread: PFN_NtSuspendThread = undefined;
pub var NtTerminateThread: PFN_NtTerminateThread = undefined;
pub var NtResumeProcess: PFN_NtResumeProcess = undefined;
pub var NtSuspendProcess: PFN_NtSuspendProcess = undefined;
pub var NtCreateJobObject: PFN_NtCreateJobObject = undefined;
pub var NtAssignProcessToJobObject: PFN_NtAssignProcessToJobObject = undefined;
pub var NtTerminateJobObject: PFN_NtTerminateJobObject = undefined;
pub var NtIsProcessInJob: PFN_NtIsProcessInJob = undefined;
pub var NtSetInformationJobObject: PFN_NtSetInformationJobObject = undefined;
pub var NtCreateThreadEx: PFN_NtCreateThreadEx = undefined;
pub var RtlCloneUserProcess: PFN_RtlCloneUserProcess = undefined;

pub fn NtCurrentProcess() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
}
pub fn NtCurrentThread() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -2))));
}
pub fn NtCurrentSession() HANDLE {
    return @ptrFromInt(@as(usize, @bitCast(@as(isize, -3))));
}

//
// USER32 function definitions
//
pub var MessageBoxA: PFN_MessageBoxA = undefined;
pub var MessageBoxW: PFN_MessageBoxW = undefined;
pub var EnumWindows: PFN_EnumWindows = undefined;
pub var GetWindowThreadProcessId: PFN_GetWindowThreadProcessId = undefined;
pub var SetForegroundWindow: PFN_SetForegroundWindow = undefined;
pub var GetForegroundWindow: PFN_GetForegroundWindow = undefined;

//
// OLE32 function definitions
//
pub var CoInitializeEx: PFN_CoInitializeEx = undefined;
pub var CoUninitialize: PFN_CoUninitialize = undefined;
pub var CoTaskMemAlloc: PFN_CoTaskMemAlloc = undefined;
pub var CoTaskMemFree: PFN_CoTaskMemFree = undefined;
pub var CoGetCurrentProcess: PFN_CoGetCurrentProcess = undefined;
pub var CoGetCallerTID: PFN_CoGetCallerTID = undefined;

//
// ADVAPI32 function definitions
//
pub var OpenProcessToken: PFN_OpenProcessToken = undefined;
pub var GetTokenInformation: PFN_GetTokenInformation = undefined;
pub var CheckTokenMembership: PFN_CheckTokenMembership = undefined;
pub var AllocateAndInitializeSid: PFN_AllocateAndInitializeSid = undefined;
pub var FreeSid: PFN_FreeSid = undefined;
pub var ConvertSidToStringSidA: PFN_ConvertSidToStringSidA = undefined;
pub var RtlGenRandom: PFN_RtlGenRandom = undefined;

//
// WS2_32 function definitions
//
pub var WSAStartup: PFN_WSAStartup = undefined;
pub var WSACleanup: PFN_WSACleanup = undefined;
pub var WSAGetLastError: PFN_WSAGetLastError = undefined;
pub var WSASocketW: PFN_WSASocketW = undefined;
pub var WSAPoll: PFN_WSAPoll = undefined;
pub var WSAGetOverlappedResult: PFN_WSAGetOverlappedResult = undefined;
pub var WSASend: PFN_WSASend = undefined;
pub var WSASendTo: PFN_WSASendTo = undefined;
pub var WSARecv: PFN_WSARecv = undefined;
pub var WSARecvFrom: PFN_WSARecvFrom = undefined;
pub var closesocket: PFN_closesocket = undefined;
pub var getaddrinfo: PFN_getaddrinfo = undefined;
pub var freeaddrinfo: PFN_freeaddrinfo = undefined;
pub var bind: PFN_bind = undefined;
pub var connect: PFN_connect = undefined;
pub var ioctlsocket: PFN_ioctlsocket = undefined;
pub var getsockopt: PFN_getsockopt = undefined;
pub var setsockopt: PFN_setsockopt = undefined;

//
// SECUR_32 function definitions
//
pub var GetUserNameExA: PFN_GetUserNameExA = undefined;

//
// "Redirectors"
// Transform "call FuncName" to "call [__imp_FuncName]", in other words enable __declspec(dllimport).
// This is necessary because Zig's libstd does not use __declspec(dllimport).
//
comptime {
    if (@import("builtin").mode != .Debug and @import("builtin").os.tag == .windows and bof) {
        @export(&NtAllocateVirtualMemory, .{ .name = "NtAllocateVirtualMemory", .linkage = .strong });
        @export(&NtFreeVirtualMemory, .{ .name = "NtFreeVirtualMemory", .linkage = .strong });
        @export(&NtDeviceIoControlFile, .{ .name = "NtDeviceIoControlFile", .linkage = .strong });
        @export(&NtFsControlFile, .{ .name = "NtFsControlFile", .linkage = .strong });
        @export(&NtLockFile, .{ .name = "NtLockFile", .linkage = .strong });
        @export(&NtUnlockFile, .{ .name = "NtUnlockFile", .linkage = .strong });
        @export(&NtQueryDirectoryFile, .{ .name = "NtQueryDirectoryFile", .linkage = .strong });
        @export(&NtQueryInformationFile, .{ .name = "NtQueryInformationFile", .linkage = .strong });
        @export(&NtQueryVolumeInformationFile, .{ .name = "NtQueryVolumeInformationFile", .linkage = .strong });
        @export(&NtQueryAttributesFile, .{ .name = "NtQueryAttributesFile", .linkage = .strong });
        @export(&NtSetInformationFile, .{ .name = "NtSetInformationFile", .linkage = .strong });
        @export(&NtReadFile, .{ .name = "NtReadFile", .linkage = .strong });
        @export(&NtWriteFile, .{ .name = "NtWriteFile", .linkage = .strong });
        @export(&NtCreateNamedPipeFile, .{ .name = "NtCreateNamedPipeFile", .linkage = .strong });
        @export(&NtCreateFile, .{ .name = "NtCreateFile", .linkage = .strong });
        @export(&NtOpenFile, .{ .name = "NtOpenFile", .linkage = .strong });
        @export(&NtFlushBuffersFile, .{ .name = "NtFlushBuffersFile", .linkage = .strong });
        @export(&LdrLoadDll, .{ .name = "LdrLoadDll", .linkage = .strong });
        @export(&LdrUnloadDll, .{ .name = "LdrUnloadDll", .linkage = .strong });
        @export(&LdrGetProcedureAddress, .{ .name = "LdrGetProcedureAddress", .linkage = .strong });
        @export(&LdrGetProcedureAddressEx, .{ .name = "LdrGetProcedureAddressEx", .linkage = .strong });
        @export(&LdrGetProcedureAddressForCaller, .{ .name = "LdrGetProcedureAddressForCaller", .linkage = .strong });
        @export(&RtlGetCurrentDirectory_U, .{ .name = "RtlGetCurrentDirectory_U", .linkage = .strong });
        @export(&RtlSetCurrentDirectory_U, .{ .name = "RtlSetCurrentDirectory_U", .linkage = .strong });
        @export(&RtlQueryPerformanceCounter, .{ .name = "RtlQueryPerformanceCounter", .linkage = .strong });
        @export(&RtlQueryPerformanceFrequency, .{ .name = "RtlQueryPerformanceFrequency", .linkage = .strong });
        @export(&RtlGetSystemTimePrecise, .{ .name = "RtlGetSystemTimePrecise", .linkage = .strong });
        @export(&RtlGetFullPathName_U, .{ .name = "RtlGetFullPathName_U", .linkage = .strong });
        @export(&RtlEqualUnicodeString, .{ .name = "RtlEqualUnicodeString", .linkage = .strong });
        @export(&RtlUpcaseUnicodeChar, .{ .name = "RtlUpcaseUnicodeChar", .linkage = .strong });
        @export(&RtlReportSilentProcessExit, .{ .name = "RtlReportSilentProcessExit", .linkage = .strong });
        @export(&RtlEnterCriticalSection, .{ .name = "RtlEnterCriticalSection", .linkage = .strong });
        @export(&RtlLeaveCriticalSection, .{ .name = "RtlLeaveCriticalSection", .linkage = .strong });
        @export(&NtClose, .{ .name = "NtClose", .linkage = .strong });
        @export(&NtQueryObject, .{ .name = "NtQueryObject", .linkage = .strong });
        @export(&NtTerminateProcess, .{ .name = "NtTerminateProcess", .linkage = .strong });
        @export(&NtWaitForSingleObject, .{ .name = "NtWaitForSingleObject", .linkage = .strong });
        @export(&NtWaitForAlertByThreadId, .{ .name = "NtWaitForAlertByThreadId", .linkage = .strong });
        @export(&NtQueryInformationProcess, .{ .name = "NtQueryInformationProcess", .linkage = .strong });
        @export(&NtQueryInformationThread, .{ .name = "NtQueryInformationThread", .linkage = .strong });
        @export(&NtCreateSection, .{ .name = "NtCreateSection", .linkage = .strong });
        @export(&NtMapViewOfSection, .{ .name = "NtMapViewOfSection", .linkage = .strong });
        @export(&NtUnmapViewOfSection, .{ .name = "NtUnmapViewOfSection", .linkage = .strong });
        @export(&NtDelayExecution, .{ .name = "NtDelayExecution", .linkage = .strong });
        @export(&NtQuerySystemInformation, .{ .name = "NtQuerySystemInformation", .linkage = .strong });
        @export(&NtCancelIoFileEx, .{ .name = "NtCancelIoFileEx", .linkage = .strong });
        @export(&CreateProcessW, .{ .name = "CreateProcessW", .linkage = .strong });
    }
}
