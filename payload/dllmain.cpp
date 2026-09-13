#include "exports.h"
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

PAYLOAD_API int __stdcall PayloadEntry(int magic)
{
    // 用于验证：映射成功 + 自定义 GetProcAddress 成功后应能调到这里
    // 自动化测试用 OutputDebugString；演示时可改回 MessageBoxA
    char buf[64];
    wsprintfA(buf, "PayloadEntry ok, magic=%d\n", magic);
    OutputDebugStringA(buf);
    return magic ^ 0x1337;
}
