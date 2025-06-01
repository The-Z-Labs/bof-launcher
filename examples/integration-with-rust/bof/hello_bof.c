#include <windows.h>

// Declare the MessageBoxA API manually
DECLSPEC_IMPORT int WINAPI USER32$MessageBoxA(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
);

// Entry point for BOF
void go(char *args, int length) {
    USER32$MessageBoxA(NULL, "Hello from BOF", "BOF Message", MB_OK | MB_ICONINFORMATION);
}
