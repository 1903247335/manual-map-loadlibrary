#include "manual_map.h"

#include <tlhelp32.h>

#include <cstdio>
#include <string>

using PayloadEntryFn = int(__stdcall*)(int);

static std::string GetSiblingPath(const char* fileName)
{
    char modulePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, modulePath, MAX_PATH);

    std::string path(modulePath);
    const auto pos = path.find_last_of("\\/");
    if (pos != std::string::npos)
        path.resize(pos + 1);
    path += fileName;
    return path;
}

static bool ModuleVisibleInSnapshot(HMODULE target)
{
    // 简单自检：Toolhelp 枚举本进程模块，看映射基址是否出现。
    // 无模块加载实现正确后，这里应返回 false。
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32First(snap, &me))
    {
        do
        {
            if (me.hModule == target)
            {
                found = true;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

int main()
{
    const std::string dllPath = GetSiblingPath("payload.dll");
    std::printf("[*] dll path: %s\n", dllPath.c_str());

    // 1) 自定义 LoadLibrary
    HMODULE mod = ManualMapLoadLibraryA(dllPath.c_str());
    if (!mod)
    {
        std::printf("[-] ManualMapLoadLibraryA failed, gle=%lu\n", GetLastError());
        std::printf("    (先把 injector/manual_map.cpp 写完)\n");
        return 1;
    }
    std::printf("[+] mapped base = %p\n", mod);

    // 2) 自定义 GetProcAddress
    auto entry = reinterpret_cast<PayloadEntryFn>(
        ManualGetProcAddress(mod, "PayloadEntry"));
    if (!entry)
    {
        std::printf("[-] ManualGetProcAddress(PayloadEntry) failed, gle=%lu\n", GetLastError());
        return 2;
    }
    std::printf("[+] PayloadEntry = %p\n", entry);

    // 3) 调用导出，验证映射可执行
    const int ret = entry(0x1234);
    std::printf("[+] PayloadEntry returned %d (expect %d)\n", ret, 0x1234 ^ 0x1337);

    // 4) 无痕迹：模块枚举不应出现该基址
    if (ModuleVisibleInSnapshot(mod))
    {
        std::printf("[-] FAIL: module is visible in Toolhelp enumeration\n");
        return 3;
    }
    std::printf("[+] PASS: not found in Toolhelp module list\n");

    // ManualFreeLibrary(mod); // 可选
    return 0;
}
