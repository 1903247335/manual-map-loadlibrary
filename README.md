# 自实现 LoadLibrary / GetProcAddress（无模块加载）

> 虽然现在有 AI，但 PE 结构仍是学习 Windows 逆向绕不过去的关卡。  
> 把基础打扎实，才能更熟练地驾驭 AI。

**完整工程（可编译、可调试）：**  
👉 https://github.com/1903247335/manual-map-loadlibrary

---

## 为什么要自己实现？

1. **把 PE / Loader 吃透**  
   弄清楚系统加载器如何把文件镜像展开到内存、如何修导入、如何做重定位。

2. **绕过一部分 R3「模块枚举」检测**  
   不调用系统 LoadLibrary / 不挂 PEB LDR 时，常见模块枚举往往看不到这块镜像，例如：

   - CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) + Module32First / Module32Next
   - EnumProcessModules / EnumProcessModulesEx
   - GetModuleHandle / GetModuleHandleEx（按名字）
   - 自行遍历：
     - PEB → Ldr → InLoadOrderModuleList
     - InMemoryOrderModuleList
     - InInitializationOrderModuleList

> 说明：这只躲开「枚举已加载模块」这一类检查，并不等于对所有 R3/R0 检测隐身。

---

## 前置知识

- 常用 Win32 API 有一定基础  
- 熟悉 PE 结构中的三块即可起步：
  - **导入表**
  - **导出表**
  - **重定位表**

本实现**不考虑 TLS**，只覆盖简单 DLL。会了这套流程，其它表也可以举一反三。

---

## 原理速览

### Manual Map ≈ 自实现 LoadLibrary

1. 把 DLL 从**文件布局**展开到**内存布局**（拷贝 PE 头 + 按节拷贝节区内容）  
2. **导入表修复**：根据 INT 解析依赖与符号，把真实地址写入 IAT  
3. **重定位修复**：把链接时按 ImageBase 写死的绝对地址，改成实际加载基址下的地址  

\\\	ext
delta     = 实际基址 - ImageBase
*patch位点 += delta
\\\

4. 找到入口，调用：

\\\	ext
DllMain(base, DLL_PROCESS_ATTACH, nullptr)
\\\

### 自实现 GetProcAddress

按**函数名**或**序号**解析导出表，得到函数地址。

### 自实现 FreeLibrary

1. DllMain(base, DLL_PROCESS_DETACH, nullptr)  
2. VirtualFree(base, 0, MEM_RELEASE)

---

## 实现思路（不贴大段代码）

文章只讲思路；完整代码见仓库 injector/manual_map.cpp。

### 1. 读入文件

\\\	ext
CreateFileA → GetFileSize → ReadFile → buffer
\\\

uffer 里是磁盘上的 PE（文件布局），方便解析 DOS / NT 头。

### 2. 文件布局 → 内存布局

1. 从 OptionalHeader.SizeOfImage 得知展开后镜像大小  
2. VirtualAlloc 申请可执行内存，得到 aseAddress  
3. 拷贝 PE 头：SizeOfHeaders（含 DOS/NT/节表）  
4. **按节拷贝节区内容**（.text / .rdata / …）  
   - 源：PointerToRawData  
   - 目的：aseAddress + VirtualAddress

> 注意：要展开的是**各个节的数据**，不只是「节表」本身。节表只是描述信息，已包含在 PE 头里。

### 3. 导入表修复

- 遍历 IMAGE_IMPORT_DESCRIPTOR  
- 从 Name 得到依赖 DLL 名；对系统 DLL 可用系统 LoadLibraryA（作业通常允许）  
- 读 **INT**（优先 OriginalFirstThunk，否则 FirstThunk）  
- 按**序号**或**名字**解析符号，写入 **IAT**（FirstThunk）

核心：**INT 负责「找谁」，IAT 负责「填地址」。**

### 4. 重定位修复

1. delta = 实际基址 - OptionalHeader.ImageBase  
2. 遍历重定位块与每条 WORD 条目（高 4 位类型，低 12 位页内偏移）  
3. 对 HIGHLOW / DIR64 等类型：在对应内存位置执行 += delta

### 5. 调用 DllMain

\\\	ext
entry = base + AddressOfEntryPoint
entry(base, DLL_PROCESS_ATTACH, nullptr)
\\\

### 6. GetProcAddress（按名 / 按序）

- 定位 IMAGE_EXPORT_DIRECTORY  
- 按名：在 AddressOfNames 里比对，用 AddressOfNameOrdinals 得到 EAT 下标，再取 AddressOfFunctions  
- 按序：unctions[ordinal - Base]

### 7. FreeLibrary

DLL_PROCESS_DETACH → VirtualFree

---

## 仓库结构

\\\	ext
ManualMap.sln          Visual Studio 解决方案（x64 Debug 可直接 F5）
injector/              手动映射实现 + 测试程序
  manual_map.cpp       ★ 核心实现
  manual_map.h
  main.cpp             加载 → 取址 → 调用 → Toolhelp 无痕迹检查
payload/               测试用 DLL（导出 PayloadEntry）
build.bat              命令行一键编译
\\\

### 编译与运行

**方式 A：Visual Studio**

1. 打开 ManualMap.sln  
2. 配置选 **Debug | x64**  
3. 启动项目设为 injector，F5 调试  

**方式 B：命令行**

在 x64 Native Tools Command Prompt 中：

\\\at
build.bat
bin\\injector.exe
\\\

### 预期输出示例

\\\	ext
[+] mapped base = ...
[+] PayloadEntry = ...
[+] PayloadEntry returned 259 (expect 259)
[+] PASS: not found in Toolhelp module list
\\\

---

## 写在最后

其实没有想象中那么难，难的是第一次把整条链路串通。  
思路清楚之后，具体代码完全可以在 AI 辅助下完成——把更多时间花在**研究原理**上，而不是死磕样板代码。

如果这篇文章对你有帮助，欢迎 Star 仓库，也欢迎指出疏漏。

**GitHub：** https://github.com/1903247335/manual-map-loadlibrary

---

*仅供学习 Windows PE / Loader 原理，请勿用于未授权场景。*
