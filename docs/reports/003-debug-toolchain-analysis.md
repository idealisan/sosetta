# 003 — Debug 工具链专项：分析报告

日期：2026-09-14
状态：设计定稿，待实现
前置：002 报告（真实 PPC 二进制验收调试，三轮迭代）

## 1. 背景与动机

002 报告的三轮调试中，所有关键 bug（字节序、section 偏移、keymgr 语义、
bsearch 回调、pc=0 干净停止）的定位都依赖临时拼凑的调试手段。每个问题的
排查循环是：运行 → grep stderr → 猜测 → capstone 手动反汇编 → symtab
最近符号查找 → 修改 → 重建 → 重跑。单次循环 5-15 分钟，本轮重复了十余次。

本专项将这套临时手段固化为一等公民的调试工具链，使后续（HTTP 请求
里程碑、resolver、OpenSSL 依赖链）的排查效率数量级提升。

## 2. 痛点分析（来自 002 实战记录）

| # | 痛点 | 本轮的临时手段 | 缺陷 | 需求 |
|---|------|--------------|------|------|
| P1 | `pc=0x83e70` 不知道是什么函数 | 手写 Python 查 symtab 最近 extdef | 每次重复；nearest-extdef 会把 static 函数误判为相邻导出函数 | R1 故障自动符号化 |
| P2 | 崩溃时无调用链 | 仅 dump sp 附近 8 字 | 无法回答"谁调用的" | R2 PPC 帧链回溯 |
| P3 | OOM 判定发生的代码位置不可见 | 事后划 codetrace 区间反复试 | 一次把 cleanup 误判为 perform（两函数相邻，tail 输出混淆） | R3 全局指令环形缓冲，崩溃时带符号 dump |
| P4 | 需要在特定地址观察状态 | 无 | 只能靠猜或全量 trace | R4 断点 |
| P5 | 逐条执行观察寄存器 | SOSETTA_CODETRACE 区间指令跟踪（仅 r2/r3/r4） | 缺 r1/lr，且硬编码在 cpu.c | R5 单步模式规范化 |
| P6 | 离线分析地址 | 内联 Python 片段 | 未入库，不可复用 | R6 离线符号化脚本 |
| P7 | 两次运行行为差异对比 | 无 | 时间依赖/堆布局差异无从下手 | R7（可选）HLE 日志落盘 |

## 3. 需求

- R1 故障符号化：任何 guest 停机（unmapped/prot/断点）自动输出 PC/LR
  的 `符号+偏移`。符号表来自 guest 二进制的 LC_SYMTAB（含 static 函数，
  curl 二进制实测 20619 个符号）。
- R2 帧链回溯：利用 darwin8 GCC 帧布局（`sp+0` 回链、`sp+8` 存 LR），
  从 r1 向栈顶走最多 16 帧，逐帧符号化。需校验帧链单调性与对齐。
- R3 指令环形缓冲：全范围 UC_HOOK_CODE 把 PC 写入环形缓冲（深度可配，
  上限 1M 条），任何停机时 dump 最近 32 条（符号化）。默认关闭
  （全范围 hook 有性能代价），`SOSETTA_RING=深度` 开启。
- R4 断点：`SOSETTA_BREAK=addr[,addr]`，命中即输出符号化报告，每断点
  限报 3 次防循环刷屏，之后自动静默。不做停机模式（观察点足够，
  停机后的恢复语义复杂且非必需）。
- R5 单步规范化：`SOSETTA_CODETRACE=begin:end` 语义保留（区间内逐条
  打印 pc/r1/r2/r3/r4），实现从 cpu.c 移入 debug 模块并补充寄存器。
- R6 离线符号化：`sosetta --symbols <binary> addr...` 子命令。实现语言
  约束：**工具链全部用 C**（符号表解析、索引、查找与 guest 侧共用
  debug 模块同一份实现，Python 原型弃用）。
- R7（可选，暂缓）：HLE 调用日志落盘。

## 4. 设计

### 4.1 架构

新增 `src/debug.c` + `include/sosetta/debug.h`（调试模块），宿主侧
单例（每次运行一个 guest）。runtime 加载完成后调用
`sosetta_debug_init(guest, &im)`：解析符号表建索引、按环境变量安装钩子。

```
runtime.c ──init──> debug.c ──UC_HOOK_*──> unicorn
    │                  │
    └──故障路径────> sosetta_debug_report(guest, reason, pc)
                         ├─ 符号化 PC/LR（symtab 二分查找）
                         ├─ GPR 全量 dump
                         ├─ 帧链回溯（r1 起最多 16 帧）
                         └─ 环形缓冲最近 32 条（若启用）
```

### 4.2 符号表索引

- 数据源：`im->symoff/stroff`（N_SECT 类型、value>0 的符号，含 extdef
  与 static）。curl 实测 20619 符号全量索引。
- 索引：`{addr, symidx}` 数组按 addr 排序（qsort），查找为二分
  （最大的 addr ≤ 目标）。
- 名字：延迟解析（strx → filebuf 内字符串），生命周期与 runtime 一致。
- 输出格式：`符号+0x偏移`；无匹配时 `0x%08x`。

### 4.3 帧链回溯算法

darwin8 GCC 帧布局：`stwu r1,-N(r1)` 后 `sp+0`=调用者 sp、`sp+8`=LR。
从 r1 起：

```
frame = r1
loop ≤16 次:
  lr  = [frame+8]   → 符号化输出
  next = [frame]    → 回链
  校验: next 按 4 对齐、next > frame（栈向低地址生长，回链向高地址）、
        next 位于栈区间 → 否则终止
  frame = next
```

起始两项为故障 PC 与 LR（叶子函数帧可能不完整，如实标注）。

### 4.4 环形缓冲

- 深度：`SOSETTA_RING`（条数，2 的幂，上限 1M；未设则关闭）
- 写入：全范围 UC_HOOK_CODE（begin=1, end=0xffffffff），每条指令写 PC
- dump：停机时最近 32 条，逐条符号化
- 已知代价：全范围 hook 使模拟速度下降一个数量级，仅调试运行启用

### 4.5 断点

- `SOSETTA_BREAK` 逗号分隔地址列表，每地址一个 UC_HOOK_BLOCK
  （begin=end=addr）
- 命中：打印符号化 PC + r1-r4/r30/lr + 帧回溯；每断点最多报 3 次
- 命中后继续执行（不做停机恢复语义；配合 SOSETTA_CODETRACE 可观察
  后续流）

### 4.6 与现有设施的关系

- `SOSETTA_TRACE`（HLE 调用跟踪、syscall 跟踪）保留在原位
- `SOSETTA_WATCH`（写监视点）保留在 cpu.c，输出改用 debug 模块符号化
- `SOSETTA_CODETRACE` 从 cpu.c 移入 debug 模块（功能不变，寄存器增强）
- cpu.c 的块级环形缓冲与 `sosetta_guest_dump_trace` 由 debug 模块
  取代，从错误路径移除

## 5. 非目标

- gdb remote stub（复杂度高，当前痛点不涉及）
- guest 侧代码插桩
- 全量内存快照与 diff
- 反汇编器集成（继续用 WSL capstone 离线分析）
- Python/脚本类工具（约束：工具链尽量全用 C）

## 6. 验收标准（总结报告逐项核对）

1. curl 真实运行崩溃时输出符号化 PC/LR/回溯（以 `Curl_ssl_free_certinfo`
   清理崩溃为实测用例）
2. `SOSETTA_BREAK=0x5e228` 能观察到 `Curl_multi_handle` 失败出口是否
   命中（002 报告遗留问题：OOM 判定是否走该出口）
3. `SOSETTA_RING` 崩溃 dump 能展示 OOM 判定前的指令流
4. symbolize.py 对本轮已知地址（0x83e70、0x84958、0x748f0）输出与
   手工分析一致
5. CTest 5/5 无回归；SOSETTA_RING/BREAK 未启用时无性能影响
