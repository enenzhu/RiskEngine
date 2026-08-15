import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import compare_clustering_reports as comparator


def signal(name, scope, value, tolerance=None, severity="high"):
    return {
        "name": name,
        "scope": scope,
        "severity": severity,
        "sourceField": name,
        "value": value,
        "available": True,
        "numericTolerance": tolerance,
        "rationale": "test",
    }


class CompareClusteringReportsTest(unittest.TestCase):
    def sample(self, physical, identity, target, signals):
        return comparator.Sample(
            physical=physical,
            identity=identity,
            path=Path(f"{physical}-{identity}.json"),
            target=target,
            signals={item["name"]: item for item in signals},
        )

    def test_detects_identity_collision_and_confirmed_physical_anchor(self):
        samples = [
            self.sample("p6a", "a1", "Samsung/S23", [
                signal("identity.boot_id", "identity", "same-a"),
                signal("physical.sensor_ids", "physical_candidate", "sensor-a"),
            ]),
            self.sample("p6a", "a2", "Xiaomi/13", [
                signal("identity.boot_id", "identity", "same-a"),
                signal("physical.sensor_ids", "physical_candidate", "sensor-a"),
            ]),
            self.sample("p6b", "b1", "Samsung/S23", [
                signal("identity.boot_id", "identity", "b-one"),
                signal("physical.sensor_ids", "physical_candidate", "sensor-b"),
            ]),
            self.sample("p6b", "b2", "Xiaomi/13", [
                signal("identity.boot_id", "identity", "b-two"),
                signal("physical.sensor_ids", "physical_candidate", "sensor-b"),
            ]),
        ]
        verdicts = {(item["verdict"], item["signal"]) for item in comparator.analyze(samples)["findings"]}
        self.assertIn(("IDENTITY_COLLISION", "identity.boot_id"), verdicts)
        self.assertIn(("CONFIRMED_PHYSICAL_UNIT_ANCHOR", "physical.sensor_ids"), verdicts)

    def test_numeric_tolerance_and_cross_target_family_collision(self):
        samples = [
            self.sample("p6a", "a1", "Samsung/S23", [
                signal("physical.boot_epoch", "physical_candidate", "1000", tolerance=3.0),
                signal("family.cpu", "family", "tensor"),
            ]),
            self.sample("p6a", "a2", "Xiaomi/13", [
                signal("physical.boot_epoch", "physical_candidate", "1002", tolerance=3.0),
                signal("family.cpu", "family", "tensor"),
            ]),
        ]
        findings = comparator.analyze(samples)["findings"]
        verdicts = {(item["verdict"], item["signal"]) for item in findings}
        self.assertIn(("SUSPECTED_PHYSICAL_ANCHOR", "physical.boot_epoch"), verdicts)
        self.assertIn(("CROSS_TARGET_FAMILY_COLLISION", "family.cpu"), verdicts)

    def test_loads_combined_report_and_requires_explicit_grouping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({
                "_meta": {"device_label": "Google/Pixel"},
                "ghost": {"clusteringSignals": [signal("family.cpu", "family", "tensor")]},
            }), encoding="utf-8")
            loaded = comparator.load_sample(f"physical-1:identity-1={path}")
            self.assertEqual("Google/Pixel", loaded.target)
            self.assertIn("family.cpu", loaded.signals)
        with self.assertRaises(ValueError):
            comparator.parse_sample_spec("identity-only=report.json")

    def test_detects_frozen_dynamic_signal_across_repeated_reports(self):
        samples = [
            self.sample("p6a", "a1", "Samsung/S23", [
                signal("dynamic.meminfo", "dynamic", "MemFree=1|Cached=2", severity="medium"),
            ]),
            self.sample("p6a", "a1", "Samsung/S23", [
                signal("dynamic.meminfo", "dynamic", "MemFree=1|Cached=2", severity="medium"),
            ]),
        ]
        findings = comparator.analyze(samples)["findings"]
        frozen = next(item for item in findings if item["verdict"] == "DYNAMIC_SIGNAL_FROZEN")
        self.assertEqual("high", frozen["severity"])
        self.assertEqual("dynamic.meminfo", frozen["signal"])

        output = io.StringIO()
        with redirect_stdout(output):
            comparator.print_human(comparator.analyze(samples))
        self.assertIn("physical=p6a identity=a1", output.getvalue())

    def test_detects_dynamic_snapshot_reused_across_identities(self):
        samples = [
            self.sample("p6a", identity, target, [
                signal("dynamic.meminfo", "dynamic", "MemFree=1|Cached=2", severity="medium"),
            ])
            for identity, target in (
                ("a1", "Samsung/S23"),
                ("a1", "Samsung/S23"),
                ("a2", "Xiaomi/13"),
                ("a2", "Xiaomi/13"),
            )
        ]

        findings = comparator.analyze(samples)["findings"]
        global_frozen = next(
            item for item in findings
            if item["verdict"] == "CROSS_IDENTITY_DYNAMIC_FROZEN"
        )
        self.assertEqual(["a1", "a2"], global_frozen["identities"])
        self.assertEqual("high", global_frozen["severity"])


if __name__ == "__main__":
    unittest.main()
