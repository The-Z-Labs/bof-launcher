#include "beacon.h"
#include "stb_sprintf.h"

// Defined in Zig code.
void* allocateMemory(unsigned long size);
void outputBofData(int type, char* data, int len, int free_mem);

void BeaconPrintf(int type, char* fmt, ...) {
    va_list args;

    if (fmt[0] == '%' && fmt[1] == 'l' && fmt[2] == 's' && fmt[3] == '\0') {
        va_start(args, fmt);
        const unsigned short* str_utf16 = (unsigned short *)va_arg(args, char *);
        va_end(args);

        int len = 0;
        const unsigned short* str = str_utf16;
        while (*str) {
            if (*str < 0x80) {
                str += 1;
                len += 1;
            } else if (*str < 0x800) {
                str += 1;
                len += 2;
            } else if (*str >= 0xd800 && *str < 0xdc00) {
                str += 2;
                len += 4;
            } else if (*str >= 0xdc00 && *str < 0xe000) {
                return;
            } else {
                str += 1;
                len += 3;
            }
        }
        len += 1;

        char* buffer = allocateMemory(len);
        if (buffer == NULL) {
            return;
        }

        int i = 0;
        str = str_utf16;
        while (*str) {
            if (*str < 0x80) {
                buffer[i++] = (char) *str++;
            } else if (*str < 0x800) {
                buffer[i++] = 0xc0 + (*str >> 6);
                buffer[i++] = 0x80 + (*str & 0x3f);
                str += 1;
            } else if (*str >= 0xd800 && *str < 0xdc00) {
                unsigned int c;
                c = ((str[0] - 0xd800) << 10) + ((str[1]) - 0xdc00) + 0x10000;
                buffer[i++] = 0xf0 + (c >> 18);
                buffer[i++] = 0x80 + ((c >> 12) & 0x3f);
                buffer[i++] = 0x80 + ((c >>  6) & 0x3f);
                buffer[i++] = 0x80 + ((c      ) & 0x3f);
                str += 2;
            } else if (*str >= 0xdc00 && *str < 0xe000) {
                return;
            } else {
                buffer[i++] = 0xe0 + (*str >> 12);
                buffer[i++] = 0x80 + ((*str >> 6) & 0x3f);
                buffer[i++] = 0x80 + ((*str     ) & 0x3f);
                str += 1;
            }
        }
        buffer[i] = 0;

        outputBofData(0, buffer, len, 1);
    } else {
        va_start(args, fmt);
        int len = stbsp_vsnprintf(NULL, 0, fmt, args) + 1;
        va_end(args);

        char* data = allocateMemory(len);
        if (data == NULL) {
            return;
        }

        va_start(args, fmt);
        len = stbsp_vsnprintf(data, len, fmt, args);
        va_end(args);

        outputBofData(0, data, len, 1);
    }
}

void BeaconOutput(int type, char* data, int len) {
    outputBofData(type, data, len, 0);
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int len = stbsp_vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (format->length + len >= format->size) {
        return;
    }

    va_start(args, fmt);
    stbsp_vsnprintf(format->buffer, len + 1, fmt, args);
    va_end(args);

    format->length += len;
    format->buffer += len;
}
