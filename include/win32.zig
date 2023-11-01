const std = @import("std");
const windows = std.os.windows;

pub const Win32Error = windows.Win32Error;
pub const ULONG = windows.ULONG;
pub const WCHAR = windows.WCHAR;
pub const LPCSTR = windows.LPCSTR;
pub const WINAPI = windows.WINAPI;
pub const HMODULE = windows.HMODULE;
pub const FARPROC = windows.FARPROC;
pub const HANDLE = windows.HANDLE;
pub const DWORD = windows.DWORD;
pub const BOOL = windows.BOOL;
pub const TRUE = windows.TRUE;
pub const FALSE = windows.FALSE;
pub const OSVERSIONINFOW = windows.OSVERSIONINFOW;
pub const RTL_OSVERSIONINFOW = windows.RTL_OSVERSIONINFOW;
pub const PVOID = windows.PVOID;
pub const PSECURITY_DESCRIPTOR = PVOID;
pub const NTSTATUS = windows.NTSTATUS;
pub const CLIENT_ID = windows.CLIENT_ID;
pub const UNICODE_STRING = windows.UNICODE_STRING;
pub const USHORT = windows.USHORT;
pub const BOOLEAN = windows.BOOLEAN;
pub const SIZE_T = windows.SIZE_T;
pub const UCHAR = windows.UCHAR;

pub const INFINITE = windows.INFINITE;
pub const WAIT_FAILED = windows.WAIT_FAILED;

pub const MEM_COMMIT = windows.MEM_COMMIT;
pub const MEM_RESERVE = windows.MEM_RESERVE;
pub const MEM_FREE = windows.MEM_FREE;
pub const MEM_RESET = windows.MEM_RESET;
pub const MEM_RESET_UNDO = windows.MEM_RESET_UNDO;
pub const MEM_LARGE_PAGES = windows.MEM_LARGE_PAGES;
pub const MEM_PHYSICAL = windows.MEM_PHYSICAL;
pub const MEM_TOP_DOWN = windows.MEM_TOP_DOWN;
pub const MEM_WRITE_WATCH = windows.MEM_WRITE_WATCH;
pub const MEM_COALESCE_PLACEHOLDERS = windows.MEM_COALESCE_PLACEHOLDERS;
pub const MEM_RESERVE_PLACEHOLDERS = windows.MEM_RESERVE_PLACEHOLDERS;
pub const MEM_DECOMMIT = windows.MEM_DECOMMIT;
pub const MEM_RELEASE = windows.MEM_RELEASE;

pub const PAGE_EXECUTE = windows.PAGE_EXECUTE;
pub const PAGE_EXECUTE_READ = windows.PAGE_EXECUTE_READ;
pub const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
pub const PAGE_EXECUTE_WRITECOPY = windows.PAGE_EXECUTE_WRITECOPY;
pub const PAGE_NOACCESS = windows.PAGE_NOACCESS;
pub const PAGE_READONLY = windows.PAGE_READONLY;
pub const PAGE_READWRITE = windows.PAGE_READWRITE;
pub const PAGE_WRITECOPY = windows.PAGE_WRITECOPY;
pub const PAGE_TARGETS_INVALID = windows.PAGE_TARGETS_INVALID;
pub const PAGE_TARGETS_NO_UPDATE = windows.PAGE_TARGETS_NO_UPDATE;
pub const PAGE_GUARD = windows.PAGE_GUARD;
pub const PAGE_NOCACHE = windows.PAGE_NOCACHE;
pub const PAGE_WRITECOMBINE = windows.PAGE_WRITECOMBINE;

pub const READ_CONTROL = 0x00020000;

pub const STANDARD_RIGHTS_REQUIRED = 0x000F0000;

pub const STANDARD_RIGHTS_READ = READ_CONTROL;
pub const STANDARD_RIGHTS_WRITE = READ_CONTROL;
pub const STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

pub const STANDARD_RIGHTS_ALL = 0x001F0000;

pub const SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

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

pub const TOKEN_INFORMATION_CLASS = enum(u32) {
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

// kernel32
pub const VirtualAlloc = windows.kernel32.VirtualAlloc;
pub const VirtualFree = windows.kernel32.VirtualFree;
pub const WriteFile = windows.kernel32.WriteFile;
pub const GetLastError = windows.kernel32.GetLastError;
pub const Sleep = windows.kernel32.Sleep;
pub const ExitProcess = windows.kernel32.ExitProcess;
pub const GetCurrentProcess = windows.kernel32.GetCurrentProcess;
pub const WaitForSingleObject = windows.kernel32.WaitForSingleObject;

pub extern "kernel32" fn GetModuleHandleA(
    lpModuleName: ?LPCSTR,
) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn LoadLibraryA(
    lpLibFileName: LPCSTR,
) callconv(WINAPI) ?HMODULE;

pub extern "kernel32" fn GetProcAddress(
    hModule: HMODULE,
    lpProcName: LPCSTR,
) callconv(WINAPI) ?FARPROC;

// ntdll
pub const RtlGetVersion = windows.ntdll.RtlGetVersion;

pub extern "ntdll" fn RtlCloneUserProcess(
    ProcessFlags: ULONG,
    ProcessSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    ThreadSecurityDescriptor: ?PSECURITY_DESCRIPTOR,
    DebugPort: ?HANDLE,
    ProcessInformation: *RTL_USER_PROCESS_INFORMATION,
) callconv(WINAPI) NTSTATUS;

// advapi32
pub extern "advapi32" fn OpenProcessToken(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *HANDLE,
) callconv(WINAPI) BOOL;

// user32
pub const MessageBoxA = windows.user32.MessageBoxA;

// ole32
pub const CoInitializeEx = windows.ole32.CoInitializeEx;
pub const CoUninitialize = windows.ole32.CoUninitialize;
pub const CoTaskMemAlloc = windows.ole32.CoTaskMemAlloc;
pub const CoTaskMemFree = windows.ole32.CoTaskMemFree;
pub const CoGetCurrentProcess = windows.ole32.CoGetCurrentProcess;
