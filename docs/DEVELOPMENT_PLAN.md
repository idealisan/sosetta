# SOSETTA 研发计划（v0.1）

> 依据《PowerPC转译工具研发方案.md》制定。目标：在 x86-64 / ARM64 宿主（macOS 与 Linux）上透明运行 32/64 位 PowerPC Mac 应用程序的动态二进制转译工具。

## 工程决策（已评审确认）

| 维度 | 决策 | 说明 |
| ---- | ---- | ---- |
| 转译引擎路线 | 基于 Unicorn Engine 起步（2.1.4 固定版本） | 封装良好、独立静态链接、可快速验证端序处理与指令转译；后续在 Hot-Path 引入自研 IR/超级优化 |
| 实现语言 | 纯 C（C11 + CMake） | 贴近 Unicorn/QEMU 生态；跨平台 CI 简单；无额外运行时依赖 |
| 首选宿主 | Linux x86-64 | 与 GitHub Actions 免费 runner 一致；作为 CI 主验证目标 |
| 构建/CI | GitHub Actions + CMake + CTest | 每次提交自动构建并运行全部测试；Unicorn 以 FetchContent 固定版本源码构建 |
| 本地开发环境 | WSL Ubuntu-22.04（与 CI 对齐） | 本机 Windows，通过 WSL 复现 Linux 构建链 |
| 测试固件 | 手工构造的最小 PPC Mach-O 二进制 + 裸 PPC 机器码 | 不依赖跨平台 PPC 编译链，保证 CI 可复现 |

## 总体技术架构（对应调研方案四大子系统）

```
┌───────────────────────────────────────────────┐
│  sisetta CLI（runtime/main.c）                │
│  Mach-O 装载 → CPU 初始化 → 执行直到退出        │
├──────────────┬───────────────┬────────────────┤
│ Mach-O 装载器 │ DBT 转译核心   │ 系统调用适配层  │
│ (src/macho.c) │ (src/cpu.c     │ (src/syscall.c)│
│ 大端解析/映射  │  Unicorn PPC32 │ 指针封送      │
│ stack/argv    │  BE 访存       │ errno 映射    │
├──────────────┴───────────────┴────────────────┤
│  Unicorn Engine 2.1.4（静态链接，FetchContent）│
└───────────────────────────────────────────────┘
```

- **Mach-O 装载器**：解析大端 `mach_header`/`segment_command`/`symtab`/`unixthread`，把段 `mmap` 进 guest 虚拟地址空间，搭建 PowerPC 大端栈（argv/envp/apple 向量）。
- **DBT 转译核心**：Unicorn PPC32 + Big-Endian 模式；`UC_HOOK_INTR` 拦截 `sc`；宿主寄存器为小端形态、guest 内存保持大端（本方案文档的“寄存器本地方向，内存源架构方向”原则由 Unicorn 自身保证）。
- **系统调用适配层**：抽取 GPR0（号）+ GPR3–GPR10（参数），对大端结构体做封送（Marshalling）与字节序转置，映射至宿主 Linux 系统调用，返回前反转回大端。
- **高层垫片层（预留）**：后续阶段实现符号级 HLE，将 libSystem/CoreFoundation 调用重定向至宿主 Native 库。

## 分阶段研发计划（沿用调研方案四阶段）

### 第一阶段：转译引擎核心 + Mach-O 装载器（当前，目标 1–4 个月）

> 目标：在 Linux x86-64 上成功装载并转译执行 PowerPC 纯计算/纯控制流 CLI 程序（阶乘、矩阵乘、Hello World）。

| 里程碑 | 内容 | 验收标准（CI 自动执行） | 状态 |
| ---- | ---- | ---- | ---- |
| M1 工程骨架 | CMake 工程 + Unicorn FetchContent + .github/workflows/ci.yml | Ubuntu-22.04 上 configure+build+ctest 全绿 | 已完成 |
| M2 Mach-O 解析 | 大端 `mach_header`/segment/symtab/unixthread 解析；Fat Binary 支持 | 解析测试通过：字段端序、段地址与保护、入口寄存器 | 已完成 |
| M3 转译核心 | Unicorn PPC32-BE 初始化；字节序访存校验；`sc` 中断钩子 | 裸机器码测试：算术/逻辑/访存/分支经由大端内存在旬正确 | 已完成 |
| M4 系统调用层 | write/read/open/close/exit 等 POSIX 子集 + errno 映射 | 集成测试：guest 内 `write` 输出落盘正确、exit 码正确 | 已完成 |
| M5 运行时驱动 | stack/argv/envp 搭建；`LC_UNIXTHREAD` 入口；CLI `sisetta <macho> [args]` | 端到端：手工 PPC Mach-O 打印 "Hello from PowerPC!" 后以 0 退出 | 已完成 |

### 当前进度（M1–M5 验收）

- 本地验证：WSL Ubuntu-22.04（gcc 11.4）上 `cmake --build` + `ctest` 全绿：
  - `test_macho`：大端解析、segment 保护、Fat Binary 字段端序。
  - `test_cpu`：算术/访存/分支、`sc` 中断钩子（pc 推进、exit code 42、无钩子时报错）。
  - `test_syscall`：write/read/lseek/exit 与错误路径（-EFAULT/-EBADF errno 映射、fd 重定向捕获）。
  - `test_integration`：hello 输出 20 字节、argc=3 读取正确。
  - `e2e_hello`：`sosetta` CLI 吞入手工 Mach-O 打印 "Hello from PowerPC!" 以 0 退出。
- 说明：Unicorn 2.1.4 的 CMake 配置期依赖 `pkg-config`（CI 已显式安装）；本地 WSL 无 sudo 时以 `pkg-config` shim 前缀 PATH 绕过。

### 第二阶段：系统调用扩展 + 浮点/向量支持（第 5–8 个月）

- 扩展 POSIX/BSD 调用集（mmap、lseek、gettimeofday、stat 等）与结构体封送。
- 启动面向 macOS 宿主的 32→64 位升轨器调研；Linux 侧对接 darlingserver 的 Mach 端口模拟。
- 引入 PowerPC 浮点（FPR）与 AltiVec（VR）转译验证。
- 目标：稳定运行 PPC 版 Python/Perl 与 Unix 基础工具链。

### 第三阶段：动态链接 + API HLE 垫片层（第 9–12 个月）

- 实现 Mach-O 动态符号绑定拦截（Stub Helper / Lazy Symbol Pointer 改写）。
- libSystem.B.dylib / CoreFoundation 核心 HLE 垫片，重定向至宿主 Native 库。
- C++ vtable 布局映射与 `objc_msgSend` 接管机制。
- 目标：运行基于 Cocoa/Carbon 的 GUI 应用。

### 第四阶段：代码生成优化 + 兼容性攻坚（第 13–18 个月）

- 转译块直接链接（Direct Block Chaining）与两级跳跃缓存评估。
- `lwarx/stwcx.` 原子指令向 x86-64 `lock` / ARM64 `ldxr/stxr` 的正确映射（Unicorn 中验证语义）。
- 面向 Hot-Path 的超级优化（Peephole Superoptimizer）模式匹配。
- 目标：接近 Rosetta 1 流畅度，稳定运行经典 PPC 商业软件与游戏。

## 验收与回归策略

- 每次 PR/推送由 GitHub Actions 触发：`ubuntu-22.04` 上 `gcc -Wall -Wextra -Werror` 编译 + `ctest` 全量回归。
- 里程碑验收即“CI 全绿 + 对应测试用例覆盖”，不依赖人工环境。
- 后续新增宿主（macOS x86-64/ARM64）时以 `matrix.os` 扩展 workflow，不改动测试逻辑。