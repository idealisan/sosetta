# 004 — Debug 工具链专项：总结报告

日期：2026-09-14
前置：003 分析报告
状态：工具链已实现并验证；HTTP 里程碑未达成（关键发现见 §4）

## 1. 交付物（全部 C 实现）

| 设施 | 入口 | 状态 |
|------|------|------|
| 符号表索引（LC_SYMTAB，N_SECT 全量） | `sosetta_debug_symtab_load` | ✅ 19878 符号 |
| 故障自动符号化报告（PC/LR/GPR/回溯） | `sosetta_debug_report` | ✅ |
| PPC 帧链回溯（r1 起最多 16 帧） | 同上 | ✅（见 §3 限制） |
| 全局指令环形缓冲 | `SOSETTA_RING=深度` | ✅ |
| 断点（命中即报告，每点限 3 次） | `SOSETTA_BREAK=addr[,addr]` | ✅ |
| 单步区间跟踪（pc/r1/r2/r3/r4/lr） | `SOSETTA_CODETRACE=begin:end` | ✅（自 cpu.c 迁入） |
| 离线符号化子命令 | `sosetta --symbols <bin> addr...` | ✅ |
| 外源 free 检测 | hle.c | ✅ |

## 2. 验证实录

### 2.1 离线符号化

```
$ sosetta --symbols curl 0x83e70 0x84958 0x748f0 0x5e228
0x00083e70 = _Curl_ssl_free_certinfo.part.0+0x40
0x00084958 = _Curl_ssl_free_certinfo
0x000748f0 = _curl_share_init+0x34
0x0005e228 = _Curl_multi_handle+0x1fc
```
与手工 capstone 分析完全一致（0x748f0 确认是 share keymgr 调用返回点；
0x5e228 确认是 Curl_multi_handle 失败出口）。

### 2.2 故障符号化 + 指令环形缓冲

崩溃时自动输出：
```
fault: Invalid memory read (UC_ERR_READ_UNMAPPED)
  pc=0x00083e70 (_Curl_ssl_free_certinfo.part.0+0x40)
backtrace:
  #0 0x00083e70 (_Curl_ssl_free_certinfo.part.0+0x40)
  #1 0x00083e4c (_Curl_ssl_free_certinfo.part.0+0x1c) [lr]
recent instructions:
  -00 0x00083e70 (...)   -01 0x00083e6c (...)
  ... -11 0x003dd89c (saveGPR+0x4c) ...
```

### 2.3 断点验证（直接回答 002 遗留问题）

```
$ SOSETTA_BREAK=0x5e228,0x5e074,0x5e23c,0x5e02c,0x60f58,0x7e6d0 ...
bp[3] hit 0x0007e6d0 (_Curl_open) lr=0x00039124 (_curl_easy_init+0x8c)  ×2
```
**0x5e228/0x5e074/0x5e23c/0x5e02c/0x60f58 均未命中**——即
`Curl_multi_handle`、`curl_multi_init`、`curl_multi_add_handle` 在当前
流程中从未执行。结合 keymgr 修复后的跟踪：`curl_easy_perform` 在
easy/multi 初始化之后、multi_add 之前退出 27。

## 3. keymgr 语义攻关成果

- 三个调用点共用 key=1 但 size 不同（share=148、multi=340、easy=3080）：
  **每个调用点有自己的 keymgr 槽位**（`__nl_symbol_ptr` 中的 BSS 单元，
  真实 libSystem 为每槽填入独立 thunk），并非按 key 共享。
- pc==0 通用拦截语义已实现：r4>0 → 分配清零块入 r2/r3/r30；r4==0 →
  r30=r3（注册对象）。
- `Curl_open` 自身也走 keymgr(1, 0xc08=3080) 分配 easy 句柄。

## 4. 当前墙与初步判断

perform 在 multi 对象分配之后、`curl_multi_add_handle` 之前退出 27，
且**无任何 HLE 分配失败**。初判：某个 keymgr 注册/查询调用的返回约定
仍未命中（各站点的返回寄存器约定可能不同），或 libcurl 内部状态检查
（如 `Curl_multi_handle` 的 magic/标志位）依赖未初始化的 keymgr 区。
0x87350/0x83e70 的故障为次生症状。

## 5. 遗留与建议

1. 以 `SOSETTA_BREAK`+`SOSETTA_CODETRACE` 组合逐站核对 keymgr 注册器
   返回约定（每站点约半小时）。
2. 若 keymgr 全部对齐后仍 27，转向 libcurl 内部状态检查（对照
   easy.c/multi.c 源码，已可经代理拉取）。
3. 工具链已就位，后续排查建议全部经由新设施进行。
