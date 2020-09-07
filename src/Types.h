#pragma once

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#define CHECK_SIZE(struct, size) static_assert(sizeof(struct) == size, "Invalid struct size : \"" #struct "\"")

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;