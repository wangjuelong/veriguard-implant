# veriguard-implant

**Veriguard 平台对手模拟植入物（implant）**——府谷电力 IPv6 安全验证系统招标 §5.1 主机攻击场景的可检测对象本体。

## Upstream attribution

Forked from [OpenAEV-Platform/implant](https://github.com/OpenAEV-Platform/implant) at commit `3b16615e95d0f9187328a73fbe26c5fd38e3b18a` (release 2.3.5).

**Fork 后一次性脱钩**：两仓代码完全独立演化，不跟上游 patch / 不做 cherry-pick / 不强求协议兼容。上游归属仅作 LICENSE Apache 2.0 attribution 用途。

## Role

`veriguard-implant` 是**短命一次性二进制**，由 `veriguard-agent` 按需 drop + 启动，承载招标 §5.1 12 类主机攻击的 5 类 payload：

- **Command** — shell 命令执行（含 ART 1781 条主机用例）
- **Executable** — drop + 执行已知二进制（RAT / 提权工具 / 病毒样本）
- **FileDrop** — 落盘文件 + 权限设置（webshell / 病毒样本）
- **DnsResolution** — DNS A/AAAA/MX 查询
- **NetworkTraffic** — 自定义 TCP/UDP/ICMP 包发送

在主机内表现为可被 HIDS（甲方"云眼"）/ EDR 检测的"对手行为"——这是设计意图，不是缺陷。

## Project context

详细设计见 `wangjuelong/Veriguard` 主仓：
- Spec: `docs/superpowers/specs/2026-05-14-veriguard-agent-implant-fork-c1-c2-design.md`
- Agent ↔ Implant 调用契约：§3.3.2
- Result Pipe NDJSON 行格式：§3.3.3

## Build

```bash
cargo build --release
cargo zigbuild --target x86_64-unknown-linux-gnu --release   # cross-compile
```

CI: `.github/workflows/release.yml` (matrix 6 binary: Linux/Win/macOS × x86_64/arm64)

## License

Apache 2.0 (inherited from upstream OpenAEV-Platform/implant).
