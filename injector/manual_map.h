#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// 作业核心 1：自己实现的“LoadLibrary”
// 要求：不要调用系统 LoadLibrary / LdrLoadDll
// 目标：映射后在模块枚举（Toolhelp / EnumProcessModules / PEB LDR）中看不到痕迹
// ============================================================
HMODULE ManualMapLoadLibraryA(const char* dllPath);

// ============================================================
// 作业核心 2：自己实现的 GetProcAddress
// 要求：不要调用系统 GetProcAddress（可用自己解析导出表）
// ============================================================
FARPROC ManualGetProcAddress(HMODULE hModule, const char* procName);

// 可选：按序号导出
FARPROC ManualGetProcAddressByOrdinal(HMODULE hModule, WORD ordinal);

// 释放自己映射出去的镜像（作业可不实现，预留接口）
BOOL ManualFreeLibrary(HMODULE hModule);

#ifdef __cplusplus
}
#endif
