#include "manual_map.h"

#include <cstdio>
#include <cstring>
#include <new>

// ---------------------------------------------------------------------------
// ManualMapLoadLibraryA
// 已修好：读文件 / 校验 / 映射节 / 导入 / 重定位
// 还留给你：TLS(可选) / 调用 DllMain / return 基址 / ManualGetProcAddress
// ---------------------------------------------------------------------------

HMODULE ManualMapLoadLibraryA(const char* dllPath)
{
    HANDLE hFile = CreateFileA(
        dllPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::printf("[-] CreateFileA failed, gle=%lu\n", GetLastError());
        return nullptr;
    }

    const DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
    {
        std::printf("[-] GetFileSize failed, gle=%lu\n", GetLastError());
        CloseHandle(hFile);
        return nullptr;
    }

    BYTE* buffer = new (std::nothrow) BYTE[fileSize];
    if (!buffer)
    {
        CloseHandle(hFile);
        return nullptr;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, nullptr) || bytesRead != fileSize)
    {
        std::printf("[-] ReadFile failed, gle=%lu\n", GetLastError());
        delete[] buffer;
        CloseHandle(hFile);
        return nullptr;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::printf("[-] Invalid DOS header\n");
        delete[] buffer;
        return nullptr;
    }

    // 必须先按字节偏移，再转成 NT 头指针
    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::printf("[-] Invalid NT header\n");
        delete[] buffer;
        return nullptr;
    }

#ifdef _WIN64
    const WORD expectMachine = IMAGE_FILE_MACHINE_AMD64;
#else
    const WORD expectMachine = IMAGE_FILE_MACHINE_I386;
#endif
    if (ntHeaders->FileHeader.Machine != expectMachine)
    {
        std::printf("[-] Unsupported machine type: 0x%04X\n", ntHeaders->FileHeader.Machine);
        delete[] buffer;
        return nullptr;
    }

    const DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    auto* baseAddress = static_cast<BYTE*>(VirtualAlloc(
        nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!baseAddress)
    {
        std::printf("[-] VirtualAlloc failed, gle=%lu\n", GetLastError());
        delete[] buffer;
        return nullptr;
    }

    // 1) 拷贝 PE 头
    std::memcpy(baseAddress, buffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // 2) 按节拷贝（.text / .rdata / .idata / .edata 等一起进来）
    auto* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (section->SizeOfRawData == 0 || section->PointerToRawData == 0)
            continue;
        std::memcpy(
            baseAddress + section->VirtualAddress,
            buffer + section->PointerToRawData,
            section->SizeOfRawData);
    }

    // 映射完成后改用镜像里的 NT 头；文件缓冲可以释放
    auto* mappedNt = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);
    delete[] buffer;
    buffer = nullptr;

    // 3) 导入表修复：读 INT，写 IAT
    {
        IMAGE_DATA_DIRECTORY& importDir =
            mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress != 0 && importDir.Size != 0)
        {
            auto* importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                baseAddress + importDir.VirtualAddress);

            while (importDescriptor->Name != 0)
            {
                const char* dllName = reinterpret_cast<const char*>(
                    baseAddress + importDescriptor->Name);

                HMODULE dep = LoadLibraryA(dllName);
                if (!dep)
                {
                    std::printf("[-] LoadLibraryA(%s) failed, gle=%lu\n", dllName, GetLastError());
                    VirtualFree(baseAddress, 0, MEM_RELEASE);
                    return nullptr;
                }

                // INT：优先 OriginalFirstThunk；没有则用 FirstThunk
                const DWORD oftRva = importDescriptor->OriginalFirstThunk
                    ? importDescriptor->OriginalFirstThunk
                    : importDescriptor->FirstThunk;

                auto* intThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + oftRva);
                auto* iatThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                    baseAddress + importDescriptor->FirstThunk);

                while (intThunk->u1.AddressOfData != 0)
                {
                    FARPROC proc = nullptr;
                    if (IMAGE_SNAP_BY_ORDINAL(intThunk->u1.Ordinal))
                    {
                        proc = GetProcAddress(
                            dep,
                            MAKEINTRESOURCEA(IMAGE_ORDINAL(intThunk->u1.Ordinal)));
                    }
                    else
                    {
                        auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                            baseAddress + intThunk->u1.AddressOfData);
                        proc = GetProcAddress(dep, reinterpret_cast<LPCSTR>(ibn->Name));
                    }

                    if (!proc)
                    {
                        std::printf("[-] GetProcAddress failed, gle=%lu\n", GetLastError());
                        VirtualFree(baseAddress, 0, MEM_RELEASE);
                        return nullptr;
                    }

                    iatThunk->u1.Function = reinterpret_cast<ULONG_PTR>(proc);
                    ++intThunk;
                    ++iatThunk;
                }

                ++importDescriptor;
            }
        }
    }

    // 4) 重定位修复
    {
        IMAGE_DATA_DIRECTORY& relocDir =
            mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress != 0 && relocDir.Size != 0)
        {
            const ULONG_PTR delta =
                reinterpret_cast<ULONG_PTR>(baseAddress) - mappedNt->OptionalHeader.ImageBase;

            auto* baseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                baseAddress + relocDir.VirtualAddress);

            while (baseRelocation->VirtualAddress != 0 && baseRelocation->SizeOfBlock != 0)
            {
                const DWORD count =
                    (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto* entries = reinterpret_cast<WORD*>(baseRelocation + 1);

                for (DWORD i = 0; i < count; ++i)
                {
                    const WORD type = entries[i] >> 12;
                    const WORD offset = entries[i] & 0x0FFF;
                    BYTE* patch = baseAddress + baseRelocation->VirtualAddress + offset;

                    if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        *reinterpret_cast<DWORD*>(patch) += static_cast<DWORD>(delta);
                    }
                    else if (type == IMAGE_REL_BASED_DIR64)
                    {
                        *reinterpret_cast<ULONG_PTR*>(patch) += delta;
                    }
                    // IMAGE_REL_BASED_ABSOLUTE(0): 填充，跳过
                }

                baseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<BYTE*>(baseRelocation) + baseRelocation->SizeOfBlock);
            }
        }
    }

    // TODO(你来写):
    // 5) （可选）处理 TLS
    {
        IMAGE_DATA_DIRECTORY& tlsDir =mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if(tlsDir.VirtualAddress!=0 && tlsDir.Size!=0){



        }


    }

    // 6) 调用入口: DllMain(base, DLL_PROCESS_ATTACH, nullptr)
    {
        const DWORD entryPoint = mappedNt->OptionalHeader.AddressOfEntryPoint;
        if (entryPoint != 0)
        {
            using DllEntry = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
            auto entry = reinterpret_cast<DllEntry>(baseAddress + entryPoint);
            if (!entry(reinterpret_cast<HINSTANCE>(baseAddress), DLL_PROCESS_ATTACH, nullptr))
            {
                std::printf("[-] DllMain(DLL_PROCESS_ATTACH) returned FALSE\n");
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return nullptr;
            }
        }
    }

    return reinterpret_cast<HMODULE>(baseAddress);
}

static PIMAGE_EXPORT_DIRECTORY GetExportDirectory(BYTE* base)
{
    if (!base)
        return nullptr;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0)
        return nullptr;

    return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + dir.VirtualAddress);
}

static FARPROC RvaToProc(BYTE* base, DWORD funcRva)
{
    if (funcRva == 0)
        return nullptr;

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // 转发导出：RVA 落在导出目录范围内则是 "dll.func" 字符串（作业 payload 无此情况）
    if (funcRva >= dir.VirtualAddress && funcRva < dir.VirtualAddress + dir.Size)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return nullptr;
    }

    return reinterpret_cast<FARPROC>(base + funcRva);
}

FARPROC ManualGetProcAddress(HMODULE hModule, const char* procName)
{
    if (!hModule || !procName)
        return nullptr;

    BYTE* base = reinterpret_cast<BYTE*>(hModule);
    PIMAGE_EXPORT_DIRECTORY exportDir = GetExportDirectory(base);
    if (!exportDir)
        return nullptr;

    auto* names = reinterpret_cast<PDWORD>(base + exportDir->AddressOfNames);
    auto* nameOrdinals = reinterpret_cast<PWORD>(base + exportDir->AddressOfNameOrdinals);
    auto* functions = reinterpret_cast<PDWORD>(base + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i)
    {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (std::strcmp(name, procName) == 0)
        {
            // nameOrdinals[i] 是 EAT 下标（从 0 起），不要减 Base
            const WORD eatIndex = nameOrdinals[i];
            if (eatIndex >= exportDir->NumberOfFunctions)
                return nullptr;
            return RvaToProc(base, functions[eatIndex]);
        }
    }

    return nullptr;
}

FARPROC ManualGetProcAddressByOrdinal(HMODULE hModule, WORD ordinal)
{
    if (!hModule)
        return nullptr;

    BYTE* base = reinterpret_cast<BYTE*>(hModule);
    PIMAGE_EXPORT_DIRECTORY exportDir = GetExportDirectory(base);
    if (!exportDir)
        return nullptr;

    const DWORD ordinalBase = exportDir->Base;
    if (ordinal < ordinalBase ||
        ordinal >= ordinalBase + exportDir->NumberOfFunctions)
        return nullptr;

    auto* functions = reinterpret_cast<PDWORD>(base + exportDir->AddressOfFunctions);
    return RvaToProc(base, functions[ordinal - ordinalBase]);
}

BOOL ManualFreeLibrary(HMODULE hModule)
{
    if (!hModule)
        return FALSE;

    BYTE* base = reinterpret_cast<BYTE*>(hModule);
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    const DWORD entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    if (entryPoint != 0)
    {
        using DllEntry = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto entry = reinterpret_cast<DllEntry>(base + entryPoint);
        entry(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_DETACH, nullptr);
    }

    return VirtualFree(base, 0, MEM_RELEASE) ? TRUE : FALSE;
}

