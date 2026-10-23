# Security Check Scripts

网络安全信息检查脚本，用于在应急响应 / 安全排查初期快速收集主机安全状态快照，为后续专项排查（挖矿、C2 后门、勒索、暴力破解等）提供判断依据。

## 脚本说明

| 文件 | 适用系统 | 说明 |
|------|---------|------|
| `linux_baseline_check.sh` | Linux | 依赖少，仅用标准 coreutils 与常见工具，缺省自动跳过可选工具 |
| `Windows_Baseline_Check.ps1` | Windows | PowerShell 版，结构化 .txt 证据输出，逐模块容错 |
| `Windows_Baseline_Check.cmd` | Windows | CMD/Batch 版，逻辑与 PS1 版对应，适合无 PowerShell 限制的环境 |

## 特点

- **只读采集，不改系统**：仅收集与报告，修复动作留给分析人员
- **全英文输出**：所有输出与注释均为 ASCII 英文，避免任意区域设置的编码 / 代码页乱码问题
- **模块化采集**：按 系统信息 / 账户 / 网络 / 进程 / 启动项 / 计划任务 / 服务 / 共享 / 补丁 / 日志 / 持久化与后门线索 等维度拆分
- **时间戳证据目录**：每次运行生成带时间戳的目录，便于多次对比
- **容错运行**：单项失败不中断，报告未采集项及原因

## 使用方法

### Linux

```bash
bash linux_baseline_check.sh                          # 默认输出到 ./baseline_report
bash linux_baseline_check.sh --output /tmp/ir --skip-integrity
```

### Windows（PowerShell 版）

建议以管理员身份运行，以覆盖安全日志等完整采集：

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows_Baseline_Check.ps1
powershell -ExecutionPolicy Bypass -File .\Windows_Baseline_Check.ps1 -OutputDir D:\IR\baseline
```

### Windows（CMD 版）

```cmd
Windows_Baseline_Check.cmd
Windows_Baseline_Check.cmd D:\IR\baseline
```

> 部分模块（安全事件日志、net session、部分注册表项）需要管理员权限，脚本会继续运行并报告未能采集的项目。

## 输出内容

运行后在输出目录生成带时间戳的文件夹，内含分模块 .txt 证据文件与 `00_SUMMARY.txt` 汇总。
