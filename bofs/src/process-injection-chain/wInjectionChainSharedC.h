#include <windows.h>

typedef struct State {
    DWORD process_id;
    NTSTATUS nt_status;
    const char* shellcode;
    SIZE_T shellcode_len;
    HANDLE process_handle;
    SIZE_T base_address;
} State;
