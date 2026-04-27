# 热补丁 Demo 代码路径

## 仓库信息

- 本地仓库路径：`/Users/jask/codes/gaia`
- Git 分支：`wechatbot-integration`
- Git 提交：`0281e8579a0ce231c6473195037dbc3502986cd1`
- Git 远端：
  - `origin`：`https://github.com/707state/gaia`

## 1. 内核 Livepatch Demo：替换 `cmdline_proc_show()` 并影响 `/proc/cmdline`

### 这个 demo 做了什么

这个 demo 使用 Linux `klp_patch` livepatch 机制替换内核函数 `cmdline_proc_show()`。补丁启用后，读取 `/proc/cmdline` 时不再经过原始的内核实现，而是进入 gaia 动态生成的替换函数体。

### 配置入口

- `gaia.toml:85`
  - `[[hotpatch.kernel_livepatch]]`
- `gaia.toml:86`
  - `old_func = "cmdline_proc_show"`
- `gaia.toml:87`
  - `new_func_body = ...`
- `gaia.toml:90`
  - `func_ret = "static int"`
- `gaia.toml:91`
  - `func_args = "struct seq_file *m, void *v"`
- `gaia.toml:92`
  - `enabled = false`

### 策略与类型定义

- `gaia-xdp/src/main.rs:200`
  - `HotpatchPolicy` 中包含 `kernel_livepatch: Vec<livepatch::KernelLivepatchTarget>`
- `gaia-xdp/src/livepatch.rs:25`
  - `KernelLivepatchTarget` 定义了：
  - `old_func`
  - `new_func_body`
  - `func_ret`
  - `func_args`
  - `obj_name`
  - `enabled`

### 主启动路径

- `gaia-xdp/src/main.rs:639`
  - daemon 启动时先清理残留的 `gaia_klp_*` 模块
- `gaia-xdp/src/main.rs:645`
  - 启动时从配置中应用已启用的 kernel livepatch target
- `gaia-xdp/src/main.rs:676`
  - `apply_kernel_livepatches(...)`
- `gaia-xdp/src/main.rs:678`
  - 过滤出已启用的 target
- `gaia-xdp/src/main.rs:683`
  - 检查 livepatch 支持情况
- `gaia-xdp/src/main.rs:691`
  - 调用 `LivepatchManager::apply(...)`
- `gaia-xdp/src/main.rs:667`
  - daemon 退出时移除所有已应用的 livepatch 模块

### 核心实现路径

- `gaia-xdp/src/livepatch.rs:88`
  - `generate_module_source(...)`
  - 生成 C 内核模块源码
- `gaia-xdp/src/livepatch.rs:123`
  - 输出替换函数定义
- `gaia-xdp/src/livepatch.rs:147`
  - 输出 `struct klp_func[]`
- `gaia-xdp/src/livepatch.rs:167`
  - 输出 `struct klp_object[]`
- `gaia-xdp/src/livepatch.rs:183`
  - 输出 `struct klp_patch`
- `gaia-xdp/src/livepatch.rs:190`
  - `module_init()` 调用 `klp_register_patch(...)`
- `gaia-xdp/src/livepatch.rs:195`
  - `module_exit()` 调用 `klp_unregister_patch(...)`

### 构建与加载路径

- `gaia-xdp/src/livepatch.rs:230`
  - `detect_kernel_build_dir()`
- `gaia-xdp/src/livepatch.rs:261`
  - `check_livepatch_support()`
- `gaia-xdp/src/livepatch.rs:318`
  - `build_livepatch_module(...)`
- `gaia-xdp/src/livepatch.rs:332`
  - 生成 C 源码
- `gaia-xdp/src/livepatch.rs:338`
  - 生成 `Makefile`
- `gaia-xdp/src/livepatch.rs:348`
  - 执行 `make`
- `gaia-xdp/src/livepatch.rs:376`
  - `load_livepatch_module(...)`
- `gaia-xdp/src/livepatch.rs:390`
  - 执行 `insmod`
- `gaia-xdp/src/livepatch.rs:401`
  - 通过 `/sys/kernel/livepatch/<name>/enabled` 启用补丁
- `gaia-xdp/src/livepatch.rs:446`
  - `unload_livepatch_module(...)`
- `gaia-xdp/src/livepatch.rs:452`
  - 通过 sysfs 关闭补丁
- `gaia-xdp/src/livepatch.rs:468`
  - 执行 `rmmod`

### 模块生命周期管理器

- `gaia-xdp/src/livepatch.rs:579`
  - `LivepatchManager`
- `gaia-xdp/src/livepatch.rs:598`
  - `apply(...)`
- `gaia-xdp/src/livepatch.rs:615`
  - `remove(...)`
- `gaia-xdp/src/livepatch.rs:627`
  - `remove_all(...)`
- `gaia-xdp/src/livepatch.rs:642`
  - `cleanup_stale_modules(...)`
- `gaia-xdp/src/livepatch.rs:668`
  - `status()`

### Web/API 路径

- `gaia-xdp/src/web.rs:568`
  - `GET /api/v1/config/kernel-livepatch`
- `gaia-xdp/src/web.rs:575`
  - `POST /api/v1/config/kernel-livepatch`
- `gaia-xdp/src/web.rs:587`
  - `DELETE /api/v1/config/kernel-livepatch/{index}`
- `gaia-xdp/src/web.rs:601`
  - `PUT /api/v1/config/kernel-livepatch/{index}`
- `gaia-xdp/src/web.rs:619`
  - `GET /api/v1/kernel-livepatch/status`
- `gaia-xdp/src/web.rs:633`
  - `sync_kernel_livepatches(...)`
  - 先移除所有现有模块，再应用已启用 target
- `gaia-xdp/src/web.rs:687`
  - `POST /api/v1/kernel-livepatch/reload`

### 测试与 demo 验证路径

- `tests/test_kernel_livepatch.sh:95`
  - 为同一个 `cmdline_proc_show` target 生成独立的 livepatch C 模块
- `tests/test_kernel_livepatch.sh:103`
  - 替换函数写入 `GAIA_LIVEPATCH_TEST_ACTIVE`
- `tests/test_kernel_livepatch.sh:109`
  - `struct klp_func` 将 `cmdline_proc_show` 映射到新函数

- `tests/test_web_api.sh:304`
  - 测试 reload API
- `tests/test_web_api.sh:331`
  - 开始验证 `/proc/cmdline` 的实际效果
- `tests/test_web_api.sh:364`
  - 显式触发 reload
- `tests/test_web_api.sh:372`
  - 检查 `/proc/cmdline` 内容是否变化
- `tests/test_web_api.sh:375`
  - 检查 sysfs enabled 标志
- `tests/test_web_api.sh:388`
  - 检查 status API
- `tests/test_web_api.sh:408`
  - toggle off 触发自动移除
- `tests/test_web_api.sh:425`
  - toggle on 触发自动应用
- `tests/test_web_api.sh:433`
  - `PUT enabled=false` 触发自动移除

## 2. 用户态运行期替换 Demo：替换 `/home/jask/lua` 的 `luaB_print()`

### 这个 demo 做了什么

这个 demo 针对一个正在运行的 `/home/jask/lua` 进程，在运行期替换用户态函数 `luaB_print()`。整体机制是：

1. 解析目标进程中原函数的运行时地址。
2. 通过 `ptrace` + `__libc_dlopen_mode` 向目标进程注入一个替换 `.so`。
3. 从已注入 `.so` 中解析替换符号地址。
4. 将原函数入口覆盖为一个 trampoline 跳转。

这里的 eBPF uprobes 只负责监控和审计，不负责真正完成函数替换。

### 配置入口

- `gaia.toml:58`
  - 第一条 `/home/jask/lua` target
- `gaia.toml:67`
  - 第二条 `/home/jask/lua` target
- `gaia.toml:76`
  - 第三条 `/home/jask/lua` target
- `gaia.toml:77`
  - `binary = "/home/jask/lua"`
- `gaia.toml:78`
  - `symbol = "luaB_print"`
- `gaia.toml:79`
  - `pid = 169302`
- `gaia.toml:80`
  - `enabled = true`
- `gaia.toml:81`
  - `patch_action = "replace_function"`
- `gaia.toml:83`
  - `replace_lib = "/tmp/gaia-libs/libluaB_print.so"`

### 策略与类型定义

- `gaia-xdp/src/main.rs:208`
  - `HotpatchTarget`
- `gaia-xdp/src/main.rs:216`
  - `patch_action`
- `gaia-xdp/src/main.rs:223`
  - `replace_lib`
- `gaia-xdp/src/main.rs:227`
  - `replace_symbol`
- `gaia-xdp/src/main.rs:232`
  - `PatchAction`
- `gaia-xdp/src/main.rs:242`
  - `ReplaceFunction`

### 主启动路径

- `gaia-xdp/src/main.rs:592`
  - 尽力附加 userspace hotpatch uprobes
- `gaia-xdp/src/main.rs:595`
  - `attach_hotpatch_targets(...)`
- `gaia-xdp/src/main.rs:608`
  - 将 hotpatch 规则同步到 BPF maps
- `gaia-xdp/src/main.rs:612`
  - 应用运行期代码补丁
- `gaia-xdp/src/main.rs:616`
  - `apply_hotpatch_code_patches(...)`

### Uprobe 监控路径

- `gaia-xdp/src/main.rs:1146`
  - `attach_hotpatch_targets(...)`
- `gaia-xdp/src/main.rs:1159`
  - 加载 `uprobe_hotpatch_entry`
- `gaia-xdp/src/main.rs:1168`
  - 加载 `uretprobe_hotpatch_exit`
- `gaia-xdp/src/main.rs:1188`
  - 将入口 uprobe 挂到 `target.symbol`
- `gaia-xdp/src/main.rs:1206`
  - 将出口 uretprobe 挂到 `target.symbol`

- `gaia-xdp-ebpf/src/main.rs:452`
  - `uprobe_hotpatch_entry(...)`
- `gaia-xdp-ebpf/src/main.rs:470`
  - 注释明确说明：真正的用户态替换不是由 eBPF 完成
- `gaia-xdp-ebpf/src/main.rs:512`
  - `HOTPATCH_ACTION_REPLACE_FUNCTION`
- `gaia-xdp-ebpf/src/main.rs:514`
  - uprobe 只记录命中了替换模式的入口

### 运行期补丁分发路径

- `gaia-xdp/src/main.rs:1276`
  - `apply_hotpatch_code_patches(...)`
- `gaia-xdp/src/main.rs:1285`
  - 要求显式指定 `pid`
- `gaia-xdp/src/main.rs:1302`
  - `ReplaceFunction` 分支调用 `apply_replace_function_patch(...)`

### 替换核心路径

- `gaia-xdp/src/main.rs:2051`
  - `apply_replace_function_patch(...)`
- `gaia-xdp/src/main.rs:2059`
  - 读取 `replace_lib`
- `gaia-xdp/src/main.rs:2076`
  - 解析原始 `luaB_print` 的运行时地址
- `gaia-xdp/src/main.rs:2100`
  - 第一步：向目标进程注入替换 `.so`
- `gaia-xdp/src/main.rs:2110`
  - 第二步：解析已注入库中的替换符号
- `gaia-xdp/src/main.rs:2127`
  - 第三步：生成 trampoline 并覆盖原始入口

### 共享库注入路径

- `gaia-xdp/src/main.rs:1435`
  - `inject_shared_library(...)`
- `gaia-xdp/src/main.rs:1457`
  - 如果 `/proc/<pid>/maps` 中已经出现该库则跳过注入
- `gaia-xdp/src/main.rs:1464`
  - 在目标进程中解析 `__libc_dlopen_mode`
- `gaia-xdp/src/main.rs:1473`
  - `ptrace(PTRACE_ATTACH)`
- `gaia-xdp/src/main.rs:1508`
  - 把共享库路径字符串写入目标进程栈
- `gaia-xdp/src/main.rs:1541`
  - 设置 PC 和寄存器，远程调用 `__libc_dlopen_mode`
- `gaia-xdp/src/main.rs:1574`
  - 继续执行目标进程
- `gaia-xdp/src/main.rs:1613`
  - 从寄存器中读取返回值
- `gaia-xdp/src/main.rs:1633`
  - 恢复原始寄存器
- `gaia-xdp/src/main.rs:1645`
  - 与目标进程分离

### 符号解析路径

- `gaia-xdp/src/main.rs:1900`
  - `resolve_libc_dlopen_in_target(pid)`
- `gaia-xdp/src/main.rs:1911`
  - 解析 `/proc/<pid>/maps`
- `gaia-xdp/src/main.rs:1962`
  - 在磁盘上的 libc 中解析 `__libc_dlopen_mode` 或 `dlopen` 偏移

- `gaia-xdp/src/main.rs:1970`
  - `resolve_injected_symbol(pid, lib_path, symbol)`
- `gaia-xdp/src/main.rs:1988`
  - 解析 `/proc/<pid>/maps` 以定位已注入 `.so`
- `gaia-xdp/src/main.rs:2047`
  - 从替换 `.so` 中解析符号偏移

### Trampoline 与代码覆盖路径

- `gaia-xdp/src/main.rs:1388`
  - `aarch64` 的 `generate_trampoline(...)`
- `gaia-xdp/src/main.rs:1420`
  - `x86_64` 的 `generate_trampoline(...)`
- `gaia-xdp/src/main.rs:2128`
  - 根据替换符号地址生成 trampoline 字节
- `gaia-xdp/src/main.rs:2129`
  - 调用 `ptrace_read_and_write(...)`
- `gaia-xdp/src/main.rs:2151`
  - `ptrace_read_and_write(...)`
  - 在同一次 ptrace 会话里读取原始字节并写入新的 trampoline 字节
- `gaia-xdp/src/main.rs:2254`
  - `restore_hotpatch_code_patches(...)`
  - 用于恢复已保存原始字节的回滚辅助函数

### 相关设计说明

- `CLAUDE.md:56`
  - hotpatch 系统概述
- `CLAUDE.md:62`
  - `OverrideReturn` / `SkipCall` 使用 ptrace 机器码补丁
- `CLAUDE.md:63`
  - `ReplaceFunction` 使用 ptrace 注入 `__libc_dlopen_mode`

## 两个 demo 的快速区别

- 内核 livepatch demo：
  - 范围：内核函数替换
  - 目标：`cmdline_proc_show`
  - 影响面：`/proc/cmdline`
  - 机制：`klp_patch` 内核模块、`insmod`、sysfs 启用

- `/home/jask/lua` demo：
  - 范围：用户态函数替换
  - 目标：运行中的 `/home/jask/lua` 进程，符号 `luaB_print`
  - 影响面：后续对该用户态函数的调用
  - 机制：`ptrace` attach、远程 `dlopen`、解析替换符号、用 trampoline 覆盖函数入口
