# GAIA-XDP 测试工件目录

> 测试时间：2026-04-27  
> 测试目标：验证 GAIA-XDP release 版本在 openEuler 24.03 SP3 (AArch64) 环境下的功能和性能指标  
> 测试环境：虚拟机 `jask@192.168.64.3`，`~/codes/codes/gaia/`

---

## 目录结构

```
gaia-test-artifacts/
├── README.md                   # 本文件
├── scripts/                    # 测试脚本
│   ├── test_functional.sh      # 功能测试脚本（11组20项）
│   ├── test_performance.sh     # 性能测试脚本（CPU/内存/API延迟/吞吐量）
│   └── collect_data.sh         # 数据采集脚本（综合版）
└── reports/                    # 测试报告与数据
    └── GAIA_测试数据分析报告.md  # 完整测试报告（release版本）
```

> 详细原始 JSON 数据文件（`state_full.json`、`memory_samples.json`、`cpu_idle.json` 等）  
> 存放于虚拟机 `~/codes/codes/gaia/` 目录下。

---

## 核心测试结论（Release 版本）

| 指标 | 值 |
|------|----|
| 构建类型 | Release (`cargo build --release`) |
| 内存 RSS | **105 MB**（σ≈1KB，极稳定） |
| CPU（空闲） | **11.4%** |
| CPU（负载） | **11.15%** |
| API 延迟（state P50） | **0.90 ms** |
| API 延迟（config P50） | **0.42 ms** |
| API 延迟（klp P50） | **0.30 ms** |
| eBPF 事件吞吐量 | **8,024 events/s** |
| 功能测试通过率 | **100%（20/20）** |

---

## 测试脚本使用方式

在虚拟机 `~/codes/codes/gaia/` 目录下执行：

```bash
# 功能测试
bash test_functional.sh

# 性能测试
bash test_performance.sh

# 综合数据采集
bash collect_data.sh
```

所有脚本输出结果（JSON 格式）保存到当前目录下的对应文件中。

---

*生成时间：2026-04-27*
