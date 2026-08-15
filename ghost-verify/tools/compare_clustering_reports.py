#!/usr/bin/env python3
"""在显式物理机/虚拟身份分组下比较 ghost-verify 聚集性信号。"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class Sample:
    physical: str
    identity: str
    path: Path
    target: str
    signals: dict[str, dict[str, Any]]


def parse_sample_spec(spec: str) -> tuple[str, str, Path]:
    grouping, separator, path_text = spec.partition("=")
    if not separator or not path_text:
        raise ValueError(f"样本格式应为 PHYSICAL:IDENTITY=REPORT.json: {spec}")
    physical, separator, identity = grouping.rpartition(":")
    if not separator or not physical or not identity:
        raise ValueError(f"样本必须显式提供物理机和虚拟身份: {spec}")
    return physical, identity, Path(path_text)


def load_sample(spec: str) -> Sample:
    physical, identity, path = parse_sample_spec(spec)
    with path.open("r", encoding="utf-8") as stream:
        document = json.load(stream)
    ghost = document.get("ghost", document)
    target = (
        document.get("_meta", {}).get("device_label")
        or ghost.get("deviceLabel")
        or ghost.get("device_label")
    )
    if not target:
        raise ValueError(f"报告缺少 device_label，无法判断跨目标型号聚集: {path}")
    raw_signals = ghost.get("clusteringSignals") or ghost.get("clustering_signals")
    if not isinstance(raw_signals, list):
        raise ValueError(f"报告不含 clusteringSignals，请先用新版 ghost-verify 采集: {path}")
    signals = {
        signal["name"]: signal
        for signal in raw_signals
        if isinstance(signal, dict) and signal.get("name") and signal.get("available") is True
    }
    return Sample(physical, identity, path, str(target), signals)


def _number(value: Any) -> float | None:
    try:
        number = float(str(value))
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def equivalent(left: Any, right: Any, tolerance: float | None) -> bool:
    if tolerance is not None:
        left_number = _number(left)
        right_number = _number(right)
        if left_number is not None and right_number is not None:
            return abs(left_number - right_number) <= tolerance
    return str(left) == str(right)


def all_equivalent(values: Iterable[Any], tolerance: float | None) -> bool:
    materialized = list(values)
    return bool(materialized) and all(
        equivalent(materialized[0], value, tolerance) for value in materialized[1:]
    )


def _stable_representatives(
    samples: list[Sample],
    signal_name: str,
    grouping: str,
    tolerance: float | None,
) -> dict[str, Any]:
    values: dict[str, list[Any]] = {}
    for sample in samples:
        signal = sample.signals.get(signal_name)
        if signal is None:
            continue
        key = getattr(sample, grouping)
        values.setdefault(key, []).append(signal.get("value"))
    return {
        key: group_values[0]
        for key, group_values in values.items()
        if all_equivalent(group_values, tolerance)
    }


def analyze(samples: list[Sample]) -> dict[str, Any]:
    definitions: dict[str, dict[str, Any]] = {}
    for sample in samples:
        for name, signal in sample.signals.items():
            definitions.setdefault(name, signal)

    findings: list[dict[str, Any]] = []
    for signal_name, definition in sorted(definitions.items()):
        scope = definition.get("scope")
        tolerance = _number(definition.get("numericTolerance"))
        rationale = definition.get("rationale")
        declared_severity = str(definition.get("severity") or "medium")

        if scope == "identity":
            by_physical: dict[str, list[Sample]] = {}
            for sample in samples:
                by_physical.setdefault(sample.physical, []).append(sample)
            for physical, physical_samples in sorted(by_physical.items()):
                representatives = _stable_representatives(
                    physical_samples, signal_name, "identity", tolerance
                )
                if len(representatives) >= 2 and all_equivalent(representatives.values(), tolerance):
                    findings.append({
                        "severity": declared_severity,
                        "verdict": "IDENTITY_COLLISION",
                        "signal": signal_name,
                        "scope": scope,
                        "physical": physical,
                        "identities": sorted(representatives),
                        "values": representatives,
                        "evidence": "同一物理机的多个虚拟身份暴露相同的本应轮换值",
                        "rationale": rationale,
                        "next_step": "确认这些报告确实采自不同虚拟身份；若确认，则该值可直接串联身份",
                    })

        elif scope == "physical_candidate":
            stable_physical: dict[str, Any] = {}
            for physical in sorted({sample.physical for sample in samples}):
                physical_samples = [sample for sample in samples if sample.physical == physical]
                representatives = _stable_representatives(
                    physical_samples, signal_name, "identity", tolerance
                )
                if len(representatives) >= 2 and all_equivalent(representatives.values(), tolerance):
                    stable_physical[physical] = next(iter(representatives.values()))
            if len(stable_physical) >= 2 and not all_equivalent(stable_physical.values(), tolerance):
                findings.append({
                    "severity": declared_severity,
                    "verdict": "CONFIRMED_PHYSICAL_UNIT_ANCHOR",
                    "signal": signal_name,
                    "scope": scope,
                    "physicals": sorted(stable_physical),
                    "values": stable_physical,
                    "evidence": "值在各物理机内跨虚拟身份稳定，同时在不同物理机之间可区分",
                    "rationale": rationale,
                    "next_step": "这是已满足双机 A/B 的具体物理机锚，应优先处理或证明风控无法读取",
                })
            elif len(stable_physical) == 1:
                physical, value = next(iter(stable_physical.items()))
                findings.append({
                    "severity": "medium",
                    "verdict": "SUSPECTED_PHYSICAL_ANCHOR",
                    "signal": signal_name,
                    "scope": scope,
                    "physical": physical,
                    "value": value,
                    "evidence": "单台物理机内已跨虚拟身份稳定，但尚无第二台同型号物理机排除公共常量",
                    "rationale": rationale,
                    "next_step": "在第二台 Pixel 6 上采至少两个虚拟身份，确认该值是否随物理机变化",
                })

        elif scope == "family":
            for physical in sorted({sample.physical for sample in samples}):
                physical_samples = [sample for sample in samples if sample.physical == physical]
                representatives = _stable_representatives(
                    physical_samples, signal_name, "target", tolerance
                )
                targets = sorted(representatives)
                for index, left_target in enumerate(targets):
                    collision_targets = [left_target]
                    for right_target in targets[index + 1:]:
                        if equivalent(representatives[left_target], representatives[right_target], tolerance):
                            collision_targets.append(right_target)
                    if len(collision_targets) >= 2:
                        findings.append({
                            "severity": declared_severity,
                            "verdict": "CROSS_TARGET_FAMILY_COLLISION",
                            "signal": signal_name,
                            "scope": scope,
                            "physical": physical,
                            "targets": collision_targets,
                            "value": representatives[left_target],
                            "evidence": "同一物理机切换到不同声明机型后，仍暴露相同的稳定硬件家族画像",
                            "rationale": rationale,
                            "next_step": "结合真实同型号基线判断是合理同平台，还是 Pixel 6 物理家族未被隔离",
                        })
                        break

        elif scope == "dynamic":
            grouped: dict[tuple[str, str], list[Any]] = {}
            for sample in samples:
                signal = sample.signals.get(signal_name)
                if signal is not None:
                    grouped.setdefault((sample.physical, sample.identity), []).append(signal.get("value"))
            for (physical, identity), values in sorted(grouped.items()):
                if len(values) >= 2 and all_equivalent(values, tolerance):
                    severity = "high" if signal_name in {
                        "dynamic.meminfo", "dynamic.sensor_events"
                    } else declared_severity
                    findings.append({
                        "severity": severity,
                        "verdict": "DYNAMIC_SIGNAL_FROZEN",
                        "signal": signal_name,
                        "scope": scope,
                        "physical": physical,
                        "identity": identity,
                        "sample_count": len(values),
                        "value": values[0],
                        "evidence": "同一虚拟身份的多次独立报告返回完全相同的动态信号",
                        "rationale": rationale,
                        "next_step": "扩大采样间隔复测；meminfo/传感器统计若仍逐字一致，可确认固定快照或常量伪造",
                    })
            for physical in sorted({sample.physical for sample in samples}):
                stable_identities = {
                    identity: values[0]
                    for (group_physical, identity), values in grouped.items()
                    if group_physical == physical and len(values) >= 2
                    and all_equivalent(values, tolerance)
                }
                if len(stable_identities) >= 2 and all_equivalent(stable_identities.values(), tolerance):
                    severity = "high" if signal_name in {
                        "dynamic.meminfo", "dynamic.sensor_events"
                    } else declared_severity
                    findings.append({
                        "severity": severity,
                        "verdict": "CROSS_IDENTITY_DYNAMIC_FROZEN",
                        "signal": signal_name,
                        "scope": scope,
                        "physical": physical,
                        "identities": sorted(stable_identities),
                        "value": next(iter(stable_identities.values())),
                        "evidence": "多个虚拟身份各自重复采样稳定，且复用了完全相同的动态快照",
                        "rationale": rationale,
                        "next_step": "检查一键新机是否重建动态投影，以及底层读取是否绕过 per-identity 数据源",
                    })

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (
        severity_rank.get(str(item.get("severity")), 9),
        str(item.get("verdict")),
        str(item.get("signal")),
    ))
    return {
        "schema_version": 1,
        "sample_count": len(samples),
        "physical_count": len({sample.physical for sample in samples}),
        "identity_count": len({(sample.physical, sample.identity) for sample in samples}),
        "target_count": len({sample.target for sample in samples}),
        "finding_count": len(findings),
        "findings": findings,
    }


def print_human(result: dict[str, Any]) -> None:
    print(
        f"样本={result['sample_count']} 物理机={result['physical_count']} "
        f"虚拟身份={result['identity_count']} 目标机型={result['target_count']} "
        f"发现={result['finding_count']}"
    )
    if not result["findings"]:
        print("未形成可执行聚集性结论；这不等于没有风险，可能是样本分组不足或信号不可读。")
        return
    for finding in result["findings"]:
        context = []
        for key in ("physical", "identity"):
            if finding.get(key):
                context.append(f"{key}={finding[key]}")
        for key in ("physicals", "identities", "targets"):
            if finding.get(key):
                context.append(f"{key}={','.join(str(value) for value in finding[key])}")
        context_text = f" [{' '.join(context)}]" if context else ""
        print(
            f"[{str(finding['severity']).upper()}] {finding['verdict']} "
            f"{finding['signal']}{context_text} — {finding['evidence']}"
        )
        print(f"  下一步: {finding['next_step']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="比较 ghost-verify 报告中的跨身份/跨物理机聚集性信号",
    )
    parser.add_argument(
        "--sample",
        action="append",
        required=True,
        metavar="PHYSICAL:IDENTITY=REPORT.json",
        help="显式标注样本来源；同一参数可重复",
    )
    parser.add_argument("--json-output", type=Path, help="另存机器可读判定结果")
    args = parser.parse_args()

    try:
        samples = [load_sample(spec) for spec in args.sample]
        result = analyze(samples)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print_human(result)
    if args.json_output:
        args.json_output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
