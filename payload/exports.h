#pragma once

#ifdef PAYLOAD_EXPORTS
#define PAYLOAD_API __declspec(dllexport)
#else
#define PAYLOAD_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 注入成功后可通过自定义 GetProcAddress 拿到并调用
PAYLOAD_API int __stdcall PayloadEntry(int magic);

#ifdef __cplusplus
}
#endif
