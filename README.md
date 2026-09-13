# manual-map-loadlibrary

自实现 `LoadLibrary` / `GetProcAddress`（PE 无模块手动映射）的学习小工程。

## 能干什么

- 手动把 DLL 映射进内存（不走系统 `LoadLibrary`）
- 自己解析导出表拿函数地址
- Toolhelp 等常见模块枚举看不到该 DLL

## 怎么用

1. 用 Visual Studio 打开 `ManualMap.sln`
2. 配置选 **Debug | x64**，启动项目选 `injector`
3. F5 运行

或命令行：

```bat
build.bat
bin\injector.exe
```

## 目录

- `injector/`：手动映射实现与测试程序
- `payload/`：测试用 DLL

详细图文讲解（发帖版，含截图）可看本地笔记，或自行对照源码学习。

仅供学习 Windows PE / Loader 原理。
