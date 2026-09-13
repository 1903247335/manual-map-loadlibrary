# 自实现 LoadLibrary 和 GetProcAddress

虽然现在有 AI 了，但对于 PE 结构，仍是我们学习 Windows 逆向绕不过去的关卡。  
必须把基础打好，才能更加熟练地运用 AI。

> 完整可运行工程（含 VS 工程与源码）：  
> **https://github.com/1903247335/manual-map-loadlibrary**

---

## 为什么要自实现 LoadLibrary 和 GetProcAddress？

主要有两点：

1. **把 PE 吃得更透**  
   搞明白底层 Loader 到底是怎么把程序「加载 / 展开」进内存的。

2. **可以免掉一部分 R3 层检测**  
   不走系统 `LoadLibrary`、不挂到 PEB 模块链时，下面这类「枚举模块」往往就看不到你的 DLL：

   - `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` + `Module32First` / `Next`
   - `EnumProcessModules` / `EnumProcessModulesEx`（psapi）
   - `GetModuleHandle` / `GetModuleHandleEx`（按名字找；你的 DLL 本来也没注册名字）
   - 自己遍历：
     - `PEB → Ldr → InLoadOrderModuleList`
     - `InMemoryOrderModuleList`
     - `InInitializationOrderModuleList`

---

## 需要的前置知识

- 对常规 Win API 有一定了解  
- 熟悉 PE 结构——其实只需要会这三块就够起步：
  - 导入表原理
  - 导出表原理
  - 重定位表原理

我们的目标是：**不考虑 TLS 表**，只考虑简单的程序。  
单单会了这条链路，别的也可以举一反三。

---

## 先简单说下原理

### LoadLibrary（手动映射）

`LoadLibrary` 本质上是把 DLL 从**文件结构**直接拓展到**内存结构**，然后：

1. **导入表修复**  
   根据 INT 的信息，把 IAT 里填成真实的函数地址（从对应模块导出表解析出来）。

2. **重定位修复**  
   把「写死的地址」换成加载之后正确的地址。很简单：

   ```text
   新地址 = 目标位置原来写死的地址
          + 实际载入到内存的基地址
          - 写死的基地址（ImageBase）
   ```

   也就是常见的：

   ```text
   delta = 实际基址 - ImageBase
   *要改的那个地址 += delta
   ```

3. 修复完后找到 DLL 入口直接调用，传入 `DLL_PROCESS_ATTACH`，完成 DLL 初始化。

### GetProcAddress

根据**名字**或者**序号**，去读 DLL 的导出表，拿到对应函数地址。

### FreeLibrary

把 DLL 句柄（其实就是映射基址）传进来：

1. 找到 DLL 主入口，传入 `DLL_PROCESS_DETACH`，走卸载逻辑  
2. 再 `VirtualFree` 把内存释放掉

---

## 开始实现（只讲思路，不贴大段代码）

我不会直接把代码整坨贴出来——那样太无聊了。下面只说思路。  
想对照完整实现，直接看仓库里的 `injector/manual_map.cpp`。

### 1. 内存空间开辟（先把文件读进来）

1. `CreateFileA` 打开 DLL 路径  
2. `GetFileSize` 拿到文件大小  
3. `ReadFile` 按文件大小读进 `buffer`，做后续解析准备

此时 `buffer` 里已经是 DLL 文件结构的一比一拷贝，目的就是方便直接读 PE。

### 2. 从文件结构拓展到内存结构

1. 读 DOS 头这些都是常规操作，一路走到 `OptionalHeader`，拿到 **`SizeOfImage`**  
   - 它代表「展开到内存之后」镜像需要的大小  
2. 用 `VirtualAlloc` 真正给 DLL 开辟展开空间，得到的指针就是 **`baseAddress`**  
3. 先把 PE 头拷到 `baseAddress`：长度用 `OptionalHeader.SizeOfHeaders`  
4. 再把各个**节区内容**按节表描述拷过去：
   - 从文件偏移 `PointerToRawData`  
   - 拷到 `baseAddress + VirtualAddress`

> 补充一句：PE 头本身按文件里的样子拷即可；真正要按「内存布局」展开的，是各个节里的数据（`.text` / `.rdata` 等）。节表只是告诉你每个节该怎么搬。

### 3. 导入表修复

修复原理很直接：

- 从 **INT** 给出的信息，知道要找哪个外部 DLL、哪个函数  
- 找到地址后，填进 **IAT**，就算修好了

具体一点：

1. 从导入描述符里取出依赖 DLL 名字  
   - 因为通常是系统 DLL，这里直接系统 `LoadLibrary` 没问题  
   - 如果你不爽，也可以自己再写一套「不依赖系统加载器也能装系统 DLL」的逻辑——不过难度会大很多  
2. 拿到依赖 DLL 句柄后，看 INT 每一项是**按序号**还是**按函数名**导入  
3. 最核心的一件事：把解析到的函数地址写进对应的 IAT 槽位

记住一句话：**INT 负责告诉你找谁，IAT 负责被填成真正能调用的地址。**

### 4. 重定位表修复

这一块实际也不难：

1. 拿当前载入内存的基址，和 PE 里的 `OptionalHeader.ImageBase` 比，看差多少（`delta`）  
2. 遍历重定位表每一项，取出要改的 offset  
3. 要改的内存位置大致是：

   ```text
   patch = 当前载入基址 + 重定位页RVA + offset
   ```

4. 然后给这个位置加上 `delta`（也就是 `当前基址 - ImageBase`），重定位就成了

真的一点都不玄乎，就是「写死的绝对地址」跟着基址搬家。

### 5. 调用 DllMain

找到 `AddressOfEntryPoint`，按约定调用：

```text
DllMain(base, DLL_PROCESS_ATTACH, nullptr)
```

这样 DLL 的初始化逻辑就会跑起来。

### 6. 实现 GetProcAddress

- **按函数名**：在导出表的名字表里比对，再映射到函数地址表  
- **按序号**：同理，走导出表的序号 / Base 规则即可

### 7. FreeLibrary 实现

1. 找到 `AddressOfEntryPoint`，传入 `DLL_PROCESS_DETACH`  
2. 再 `VirtualFree` 释放整块镜像  

就这样。

---

## 写在最后

实际上并没有我们想象中那么难。  
难的是过程代码实现可能曲折一点，但**思路是摆在那的**。

现在有 AI 了，我们可以把更多时间花在研究思路上，而不是死磕样板代码。

完整工程在这里，欢迎自学对照：

**https://github.com/1903247335/manual-map-loadlibrary**

---

*仅供学习 Windows PE / Loader 原理，请勿用于未授权场景。*
