# 001 号报告：sosetta 阶段一开发进展与问题（2026-09-14）

## 1. 项目概况

sosetta：基于 Unicorn Engine 2.1.4 的 PowerPC macOS（大端 Mach-O）动态二进制转译工具。

- 语言/构建：纯 C（C11）+ CMake；Unicorn 以 FetchContent 固定版本（GIT_TAG 2.1.4）源码构建，静态链接。
- 目标宿主：Linux x86-64（与 GitHub Actions ubuntu-22.04 对齐），本机经 WSL Ubuntu-22.04 复现。
- 代码约束：`-std=c11 -Wall -Wextra -Werror`（MSVC 对应 `/W4 /WX`），仅施加于本项目 target，不作用于 Unicorn 子工程；源码不写注释。

## 2. 阶段一范围（M1–M5）与完成情况

| 里程碑 | 内容 | 状态 |
| ---- | ---- | ---- |
| M1 工程骨架 | CMake + Unicorn FetchContent + CI | 完成 |
| M2 Mach-O 解析 | 大端 header/segment/symtab/unixthread、Fat Binary（含字段端序、地址与保护） | 完成 |
| M3 转译核心 | Unicorn PPC32-BE 初始化、sc 中断钩子、字节序访存 | 完成 |
| M4 系统调用层 | write/read/open/close/lseek/mmap/munmap/unlink/getpid/exit + errno 映射 | 完成 |
| M5 运行时驱动 | stack/argv/envp 搭建、LC_UNIXTHREAD 入口、CLI、端到端 Hello | 完成 |

已提交：`fed5e8d`（阶段一主体）、`dcc41b2`（Release 修复）。均已推送 `origin/main`。

## 3. 关键设计决策

- 系统调用 ABI：`r0=系统调用号`，参数取 `r3..r10`（实现取前 8 个），返回值写 `r3`；失败返回负 Darwin errno（例如 EFAULT -> -14）。
- 错误约定：Linux errno 经 `sosetta_syscall_errno_to_darwin()` 反查为 Darwin errno 后再取负，对应关系以静态表维护。
- 访存语义：guest 内存保持大端；宿主寄存器为 Unicorn 管理的本地形态，Unicorn 自身保证转换。
- 测试固件：`tests/fixtures/macho_builder.h` 手工构造大端 PPC Mach-O（hello：write 20 字节后 exit 0；argc：`lwz r3,0(r1)` 后以 argc 退出）。
- `sc` 语义确认：触发 `UC_HOOK_INTR`（intno=8），回调前 `nip+=4`，故 sc 后 PC 指向下一条；未注册钩子时报错。

## 4. 验证结果

本地（WSL Ubuntu-22.04，cmake 3.30.5）与 CI（GitHub Actions，Debug + Release）均 5/5 通过：

- `test_macho`：大端解析、segment 保护、Fat Binary 字段端序。
- `test_cpu`：算术/访存/分支、sc 后 pc 推进、exit code 42、无钩子时 run 返回非 0。
- `test_syscall`：write/read/lseek/exit 与错误路径（-EFAULT/-EBADF 等）、fd 重定向捕获。
- `test_integration`：hello 输出 20 字节内容正确；argc 读取为 3 并以 3 退出。
- `e2e_hello`：`sosetta` CLI 执行手工 Mach-O，输出 "Hello from PowerPC!" 并以 0 退出。

CI 触发方式：`on: push`（main）+ `pull_request` + `workflow_dispatch`，矩阵 Debug/Release 全绿。

## 5. 过程中发现并解决的问题

### 5.1 构建环境类

1. Unicorn CMake 配置期执行 `sh qemu/configure`，缺 `pkg-config` 会失败且错误被静默吞掉，导致不生成 `config-host.h`/`config-target.h`，后续报 `config-target.h: No such file or directory`、`mprotect` 隐式声明。CI 已显式安装 `pkg-config`；本机 WSL 因无 sudo，用自编 pkg-config shim（回显 0.29.2、`--exists/--atleast-*` 返回 0）置于 `PATH` 前缀解决。
2. 全局 `set(CMAKE_C_STANDARD ...)` 会破坏 Unicorn 子工程编译，改为 `sosetta_setup_target()` 逐 target 设置。
3. 曾尝试给 `unicorn-common` 定义 `CONFIG_POSIX` 绕过，配置正确生成 `config-host.h`（含 `CONFIG_POSIX`）后已移除，避免重复宏定义告警。

### 5.2 代码正确性类

1. `-Werror` 系列：`darwin_to_linux_errno` 定义未用（-Wunused-function，已整体删除）、`dispatching` 传参丢 const、`intno` 未用参数、`fileno`/`lseek` 等因严格 C11 未声明（源文件加 `_POSIX_C_SOURCE 200809L`）。
2. `syscall.c` 历史缺陷：未定义 `DARWIN_SYS_wait4` 引用、unlink/未初始化返回、write 循环 `r` 未初始化、hook 中 `ret` 未初始化（`uint32_t ret = 0`）。
3. `runtime.c`：`im_has_thread_with_sp`/`has_thread_with_sp` 名称不一致 + 缺前向声明。
4. test_integration argc 连败三大根因（本次重点）：
   a. 栈布局翻转：字符串池被放在栈底、argc/argv 指针数组在字符串后，导致 `lwz r3,0(r1)` 读到 argv[0] 字符串（`0x61726763`=“argc”）而非 argc。已重排为 `0(r1)=argc`、随后 argv[]/envp 指针、字符串池位于高地址。
   b. 固件 `lwz` 编码错误：`0x80030000`（实为 `lwz r1,0(r3)`）改为 `0x80610000`（`lwz r3,0(r1)`）。
   c. 诊断流污染：测试用 `printf` 输出 check 结果，guest stdout 被 `dup2` 捕获后诊断混入捕获文件，导致内容断言失败；`check()` 改到 stderr 后定位。
   d. 断言语义修正：`sosetta_runtime_run` 语义为返回退出码而非 0，argc 用例断言改为 `== 3`。
5. Release 专属 bug（`-O3` 内联触发）：`macho_builder.h` 中 `strncpy(dst,16)`（dst 恰为 `char[16]`）触发 `-Werror=stringop-truncation`，Debug 不报、CI Release 挂。已改为始终 NUL 结尾的截断拷贝 `mf_copy_segname()`。本地以 Release（Makefiles 生成器）复验 5/5 通过。

## 6. 现存问题与风险

1. `actions/checkout@v4` 存在 Node 20 弃用告警（不影响构建），可升级 `@v5` 消除。
2. 系统调用集仍是 POSIX 最小子集；`fork` 与未知调用统一返回 `ENOSYS`，`mmap/munmap` 仅支持匿名映射（`fixed` 时要求页对齐），结构体封送（stat 等）尚未实现。
3. 运行超时固定 5s（`RUN_TIMEOUT_US`），无超时错误区分与配置。
4. 尚未支持：arm 64、64 位 guest（`is_64` 直接拒绝）、动态链接（stubs/绑定符号）、浮点/向量指令验证、多宿主（无 matrix.os 扩展）。
5. 本地 WSL 的构建依赖自编 shim/下载的 cmake，未固化到脚本；若换机器需重新手动配置或改为 apt 安装。

## 7. 下一步建议

1. 将 `actions/checkout@v4` 升级到 `@v5`（消除告警）。
2. 进入阶段二：扩展复杂系统调用与结构体封送（stat/gettimeofday/信号等）、mmap 文件映射、浮点/Altivec 验证。
3. 补充 32->64 位升轨调研与 darlingserver/mach 端口对接评估。
4. 评估将本地 WSL 的 cmake/pkg-config 准备脚本归档到 `scripts/`，简化新环境搭建。

## 8. 附：仓库结构

```
CMakeLists.txt              根构建（FetchContent unicorn 2.1.4；sosetta_setup_target）
.github/workflows/ci.yml    push/PR/dispatch 触发，ubuntu-22.04 Debug+Release
include/sosetta/            macho.h cpu.h syscall.h runtime.h endian.h
src/                        macho.c cpu.c syscall.c runtime.c main.c
tests/                      test_macho/test_cpu/test_syscall/test_integration/gen_hello/e2e_hello
tests/fixtures/             macho_builder.h
docs/                       阶段计划与方案
```