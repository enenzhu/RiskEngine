import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

import compare_restore_snapshot as audit


def fixture():
    props = {
        "manufacturer": "Synthetic", "brand": "synthetic", "model": "Test Device",
        "fingerprint": "synthetic/test/unit:14/TEST/123:user/release-keys", "name": "test_product",
        "device": "test_device", "build_id": "TEST", "release": "14", "sdk": "34",
    }
    snapshot = {"schema_version": 3, "device_id": "source-gsf-id", "device": {"props": props},
                "accounts": [{"name": "synthetic-account-sentinel", "am_token": "TOKEN_SENTINEL"}],
                "artifacts": {"gms_account_store_pb": {"value": "PB_SENTINEL"}}}
    values = [("MANUFACTURER", "Synthetic"), ("BRAND", "synthetic"), ("MODEL", "Test Device"),
              ("FINGERPRINT", props["fingerprint"]), ("PRODUCT", "test_product"),
              ("DEVICE", "test_device"), ("ID", "TEST"), ("RELEASE", "14"), ("SDK_INT", "34")]
    fields = []
    for name, value in values:
        prefix = "Build.VERSION." if name in {"RELEASE", "SDK_INT"} else "Build."
        fields.append({"name": name, "canonicalValue": value,
                       "sources": [{"source": prefix + name, "layer": "java", "value": value}]})
    state = {"status": "ok", "adopted": True, "deviceId": "running-ghost-id"}
    report = {
        "_meta": {"restore_audit": {"schemaVersion": 1, "dataKind": "live", "runId": "test-run",
                                   "startedAt": 1000, "completedAt": 2000,
                                   "before": copy.deepcopy(state), "after": copy.deepcopy(state)}},
        "ghost": {"timestamp": 1500, "fieldCount": len(fields), "fields": fields,
                  "observationContext": {"packageName": "com.ghost.verify", "processName": "com.ghost.verify",
                                         "uid": 10123, "pid": 1234, "scope": "collector_process_and_children"}},
    }
    return snapshot, report


def add_field(report, name, source, value, layer="java", **kwargs):
    report["ghost"]["fields"].append({"name": name, "sources": [dict(source=source, layer=layer, value=value, **kwargs)]})
    report["ghost"]["fieldCount"] = len(report["ghost"]["fields"])


def compare(snapshot, report):
    return audit.compare(snapshot, report, run_id="test-run", restored_device_id="running-ghost-id", not_before_ms=1000)


class CompareRestoreSnapshotTest(unittest.TestCase):
    def test_required_build_and_source_id_namespace(self):
        snapshot, report = fixture()
        result = compare(snapshot, report)
        self.assertEqual("PASS", result["verdict"])
        self.assertEqual(9, result["coverage"]["pass"])
        self.assertEqual(100, result["coverage"]["observedPercent"])

    def test_central_one_object_and_string_envelopes(self):
        snapshot, report = fixture()
        for clone_data in (snapshot, json.dumps(snapshot)):
            envelope = {"data": {"id": 123, "clone_data": clone_data}}
            self.assertEqual("PASS", compare(envelope, report)["verdict"])
        with self.assertRaises(audit.Rejected):
            compare({"data": {"clone_data": '{"schema_version":3,"schema_version":2}'}}, report)

    def test_business_app_data_is_excluded_from_device_audit_and_stdout(self):
        snapshot, report = fixture()
        baseline = compare(snapshot, report)
        snapshot["accounts"][0]["name"] = "business-owner@example.invalid"
        snapshot["app_data"] = {
            "package_versions": {"com.google.android.gms": "9007199254740993", "com.android.vending": "456000902",
                                 "com.google.android.youtube": "789000903"},
            "youtube": {"google_vistor_id": "BUSINESS_VISITOR_SENTINEL",
                        "selected_account": "business-owner@example.invalid"},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path, report_path = root / "snapshot.json", root / "report.json"
            report_path.write_text(json.dumps(report))
            inputs = [snapshot, {"data": {"id": 123, "clone_data": snapshot}},
                      {"data": {"id": 123, "clone_data": json.dumps(snapshot)}}]
            for payload in inputs:
                snapshot_path.write_text(json.dumps(payload))
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = audit.main(["--snapshot", str(snapshot_path), "--report", str(report_path),
                                       "--expected-device-id", "running-ghost-id", "--run-id", "test-run",
                                       "--not-before-ms", "1000"])
                self.assertEqual(0, code)
                self.assertEqual(baseline, json.loads(stdout.getvalue()))
                for business_value in ("BUSINESS_VISITOR_SENTINEL", "business-owner@example.invalid",
                                       "9007199254740993", "456000902", "789000903", "app_data"):
                    self.assertNotIn(business_value, stdout.getvalue())

    def test_display_memory_locale_and_epoch_units(self):
        snapshot, report = fixture()
        snapshot["device"]["props"]["build_date_utc"] = "1700000000"
        snapshot["device"]["selfProcInfo"] = {
            "totalMemory": 8589934715, "diskSize": 123456789000,
            "display": {"resolution": {"width": 1080, "height": 2400}, "dpi": 420}, "displayStr": "2400x1080",
            "locale": {"language": "en", "country": "", "variant": ""}, "localeStr": "en//", "timeZone": "Etc/UTC",
        }
        for name, source, value in [
            ("TIME", "Build.TIME", "1700000000000"),
            ("restore.total_memory_bytes", "ActivityManager.MemoryInfo.totalMem", "8589934715"),
            ("restore.disk_bytes", "StatFs.external_storage.total_bytes", "123456789000"),
            ("resolution", "DisplayMetrics.{width,height}Pixels", "1080x2400"),
            ("dpi_app_resources_java", "DisplayMetrics.densityDpi", "420"),
            ("restore.locale", "Resources.Configuration.locale", '{"language":"en","country":"","variant":""}'),
            ("restore.localeStr", "Resources.Configuration.locale", "en//"),
            ("timezone", "TimeZone.getDefault().id", "Etc/UTC"),
        ]:
            add_field(report, name, source, value)
        self.assertEqual("PASS", compare(snapshot, report)["verdict"])
        snapshot["device"]["selfProcInfo"]["totalMemory"] += 1
        result = compare(snapshot, report)
        self.assertEqual(1, result["coverage"]["mismatch"], "must not hide byte differences by rounding to MiB")
        self.assertEqual("FAIL", result["verdict"])

    def test_sensor_library_and_audio_api_contracts(self):
        snapshot, report = fixture()
        sensors = {"1": {"name": "Synthetic Accelerometer", "vendor": "Synthetic", "maxRange": 19.6133, "resolution": 0.001}}
        snapshot["device"]["systemServerData"] = {"sensorMap": sensors}
        snapshot["device"]["extraData"] = {"slibs": "lib.a lib.b", "vol_ring": "4"}
        add_field(report, "restore.sensorMap", "SensorManager.default_sensors", json.dumps(sensors))
        add_field(report, "restore.slibs", "PackageManager.getSystemSharedLibraryNames", "lib.b,lib.a")
        add_field(report, "restore.vol_ring", "AudioManager.getStreamVolume(2)", "4")
        self.assertEqual("PASS", compare(snapshot, report)["verdict"])
        snapshot["device"]["systemServerData"]["sensorMap"]["1"]["vendor"] = "OTHER"
        self.assertEqual(1, compare(snapshot, report)["coverage"]["mismatch"])

    def test_sensor_floats_compare_at_float32_precision(self):
        # Producer JSON keeps the float32 expansion, the observer prints the short form.
        snapshot, report = fixture()
        snapshot["device"]["systemServerData"] = {"sensorMap": {
            "1": {"name": "Synthetic Accelerometer", "vendor": "Synthetic",
                  "maxRange": 156.90640258789062, "resolution": 0.0005985504249110818}}}
        add_field(report, "restore.sensorMap", "SensorManager.default_sensors", json.dumps({"1": {
            "name": "Synthetic Accelerometer", "vendor": "Synthetic",
            "maxRange": 156.9064, "resolution": 0.0005985504}}))
        self.assertEqual("PASS", compare(snapshot, report)["verdict"])

    def test_boot_device_prefix_and_gaid_limited_suffix_are_canonical(self):
        def run(actual):
            snapshot, report = fixture()
            snapshot["device"]["props"]["boot_device"] = "3c400000.ufs"
            snapshot["device"]["settingData"] = {"oaid": "gaid-sentinel"}
            add_field(report, "ro.boot.boot_devices", "ro.boot.boot_devices", "soc/3c400000.ufs", layer="native")
            add_field(report, "GAID (Google Advertising ID)", "AdvertisingIdClient.Info.getId()", actual)
            return compare(snapshot, report)
        self.assertEqual("PASS", run("gaid-sentinel (limited=false)")["verdict"])
        self.assertEqual(1, run("gaid-other (limited=true)")["coverage"]["mismatch"])

    def test_new_parameter_fields_have_rules_or_explicit_reasons(self):
        snapshot, report = fixture()
        snapshot["device"]["props"].update({"cpu_abi": "arm64-v8a", "version_codename": "REL", "glsl_version": "x"})
        snapshot["device"]["selfProcInfo"] = {"runtimeFree": 1, "availableLocales": "en-US"}
        add_field(report, "CODENAME", "Build.VERSION.CODENAME", "REL")
        status = {row["field"]: row for row in compare(snapshot, report)["fields"]}
        self.assertEqual("PASS", status["props.version_codename"]["status"])
        for path, reason in (("props.cpu_abi", "abi_reported_only_as_merged_supported_list"),
                             ("props.glsl_version", "glsl_not_hooked_by_producer_path"),
                             ("selfProcInfo.runtimeFree", "jvm_free_heap_moves_constantly"),
                             ("selfProcInfo.availableLocales", "full_locale_inventory_not_observed")):
            self.assertEqual("UNOBSERVABLE", status[path]["status"])
            self.assertEqual(reason, status[path]["reason"])

    def test_brightness_is_volatile_but_still_observed(self):
        def run(actual):
            snapshot, report = fixture()
            snapshot["device"]["settingData"] = {"brightness": "128"}
            add_field(report, "SCREEN_BRIGHTNESS", "Settings.System", actual)
            return compare(snapshot, report)
        for actual in ("128", "77"):
            result = run(actual)
            row = next(row for row in result["fields"] if row["field"] == "settingData.brightness")
            self.assertEqual("UNOBSERVABLE", row["status"])
            self.assertEqual("known_volatile_value", row["reason"])
            self.assertEqual(0, result["coverage"]["mismatch"])
            self.assertEqual("PARTIAL", result["verdict"])

    def test_real_producer_space_separated_libraries_match_reordered_observer(self):
        snapshot, report = fixture()
        snapshot["device"]["extraData"] = {"slibs": "android.test.base org.apache.http.legacy android.test.mock"}
        add_field(report, "restore.slibs", "PackageManager.getSystemSharedLibraryNames",
                  "android.test.mock,android.test.base,org.apache.http.legacy")
        result = compare(snapshot, report)
        row = next(row for row in result["fields"] if row["field"] == "extraData.slibs")
        self.assertEqual("PASS", row["status"])
        self.assertEqual("PASS", result["verdict"])

    def test_real_producer_library_missing_from_observer_is_mismatch(self):
        snapshot, report = fixture()
        snapshot["device"]["extraData"] = {"slibs": "android.test.base org.apache.http.legacy android.test.mock"}
        add_field(report, "restore.slibs", "PackageManager.getSystemSharedLibraryNames",
                  "android.test.mock,android.test.base")
        result = compare(snapshot, report)
        row = next(row for row in result["fields"] if row["field"] == "extraData.slibs")
        self.assertEqual("MISMATCH", row["status"])
        self.assertEqual(1, result["coverage"]["mismatch"])
        self.assertEqual("FAIL", result["verdict"])

    def test_api21_sources_and_future_sdk_follow_service_consumer_contract(self):
        versions = [("21", "5.0"), ("22", "5.1"), ("23", "6.0"), ("24", "7.0"),
                    ("25", "7.1"), ("26", "8.0"), ("27", "8.1"), ("28", "9"),
                    ("38", "future-release"), ("34", "14-vendor")]
        for sdk, release in versions:
            with self.subTest(sdk=sdk, release=release):
                snapshot, report = fixture()
                snapshot["device"]["props"].update(sdk=sdk, release=release)
                for field in report["ghost"]["fields"]:
                    if field["name"] in {"SDK_INT", "RELEASE"}:
                        field["sources"][0]["value"] = sdk if field["name"] == "SDK_INT" else release
                self.assertEqual("PASS", compare(snapshot, report)["verdict"])

    def test_gaid_zero_or_denied_is_not_pass(self):
        snapshot, report = fixture()
        snapshot["device"]["settingData"] = {"oaid": "gaid-sentinel"}
        add_field(report, "GAID (Google Advertising ID)", "AdvertisingIdClient.Info.getId()", "00000000-0000-0000-0000-000000000000")
        self.assertEqual(1, compare(snapshot, report)["coverage"]["unobservable"])

    def test_only_successful_baseband_empty_string_is_a_comparable_value(self):
        cases = [("", "", None, "PASS"), ("modem", "", None, "MISMATCH"),
                 ("", "modem", None, "MISMATCH"), ("", None, None, "UNOBSERVABLE"),
                 ("", "", "SecurityException: denied", "UNOBSERVABLE"),
                 ("", "<denied>", None, "UNOBSERVABLE")]
        for expected, actual, error, status in cases:
            with self.subTest(actual=actual, error=error):
                snapshot, report = fixture()
                snapshot["device"]["props"]["baseband_version"] = expected
                add_field(report, "RADIO", "Build.RADIO", actual, error=error)
                result = compare(snapshot, report)
                row = next(row for row in result["fields"] if row["field"] == "props.baseband_version")
                self.assertEqual(status, row["status"])
        snapshot, report = fixture()
        report["ghost"]["fields"][0]["sources"][0]["value"] = ""
        row = next(row for row in compare(snapshot, report)["fields"] if row["field"] == "props.manufacturer")
        self.assertEqual("UNOBSERVABLE", row["status"], "other empty API values must remain unavailable")

    def test_actual_sources_override_cached_canonical_and_expected(self):
        snapshot, report = fixture()
        model = next(f for f in report["ghost"]["fields"] if f["name"] == "MODEL")
        model["sources"][0]["value"] = "ACTUAL_OTHER_MODEL"
        report["expectedEnv"] = {"build.model": snapshot["device"]["props"]["model"]}
        report["restore_diff"] = {"passed": True}
        result = compare(snapshot, report)
        self.assertEqual(1, result["coverage"]["mismatch"])
        model["sources"][0]["layer"] = "expected"
        self.assertEqual(1, compare(snapshot, report)["coverage"]["missing"])

    def test_missing_field_and_permission_skip_are_separate(self):
        snapshot, report = fixture()
        report["ghost"]["fields"].pop()
        report["ghost"]["fieldCount"] -= 1
        report["ghost"]["fields"][0]["sources"][0].update(value=None, error="SecurityException:SECRET_SENTINEL")
        result = compare(snapshot, report)
        self.assertEqual("FAIL", result["verdict"])
        self.assertEqual(1, result["coverage"]["missing"])
        self.assertEqual(1, result["coverage"]["unobservable"])
        self.assertEqual(7, result["coverage"]["observed"])
        self.assertNotIn("SECRET_SENTINEL", json.dumps(result))

    def test_cross_uid_ssaid_never_compared_to_verify_android_id(self):
        snapshot, report = fixture()
        snapshot["device"]["extraData"] = {"ssaid_vending": "play-ssaid-sentinel"}
        snapshot["device"]["settingData"] = {"oaid": "gaid-sentinel"}
        add_field(report, "ANDROID_ID", "Settings.Secure.ANDROID_ID", "play-ssaid-sentinel")
        add_field(report, "GAID (Google Advertising ID)", "AdvertisingIdClient.Info.getId()", "gaid-sentinel")
        result = compare(snapshot, report)
        self.assertEqual("PARTIAL", result["verdict"])
        self.assertEqual(1, result["coverage"]["unobservable"])
        self.assertEqual(10, result["coverage"]["pass"])
        self.assertLess(result["coverage"]["passPercent"], 100)
        self.assertNotIn("play-ssaid-sentinel", json.dumps(result))

    def test_locale_variant_and_build_case_are_not_discarded(self):
        snapshot, report = fixture()
        report["ghost"]["fields"][0]["sources"][0]["value"] = "synthetic"
        snapshot["device"]["selfProcInfo"] = {"locale": {"language": "en", "country": "US", "variant": "POSIX"}}
        add_field(report, "restore.locale", "Resources.Configuration.locale", '{"language":"en","country":"US","variant":""}')
        self.assertEqual(2, compare(snapshot, report)["coverage"]["mismatch"])

    def test_rejects_stale_synthetic_unadopted_or_changed_identity(self):
        mutations = [
            lambda r: r["_meta"].clear(),
            lambda r: r["_meta"]["restore_audit"].update(runId="old-run"),
            lambda r: r["_meta"]["restore_audit"].update(dataKind="synthetic"),
            lambda r: r["_meta"]["restore_audit"].update(startedAt=999),
            lambda r: r["_meta"]["restore_audit"]["before"].update(adopted=False),
            lambda r: r["_meta"]["restore_audit"]["after"].update(deviceId="different-device"),
            lambda r: r["_meta"]["restore_audit"]["after"].update(status="unavailable"),
            lambda r: r["ghost"].update(timestamp=999),
            lambda r: r["ghost"]["observationContext"].update(packageName="com.google.android.gms"),
            lambda r: r["ghost"]["observationContext"].update(scope="config_projection"),
            lambda r: r["ghost"].update(fields=[], fieldCount=0),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                snapshot, report = fixture()
                mutation(report)
                with self.assertRaises(audit.Rejected):
                    compare(snapshot, report)

    def test_rejects_no_actual_observations_and_duplicate_sources(self):
        snapshot, report = fixture()
        for field in report["ghost"]["fields"]:
            field["sources"] = []
        with self.assertRaisesRegex(audit.Rejected, "no_actual_observations"):
            compare(snapshot, report)
        snapshot, report = fixture()
        field = report["ghost"]["fields"][0]
        field["sources"].append(copy.deepcopy(field["sources"][0]))
        with self.assertRaisesRegex(audit.Rejected, "duplicate_source"):
            compare(snapshot, report)

    def test_schema3_allowlist_and_bad_build_rejected(self):
        mutations = [
            lambda s: s.update(schema_version=2),
            lambda s: s["device"].update(config_projection={}),
            lambda s: s["device"]["props"].update(android_id="not-global"),
            lambda s: s["device"]["props"].update(sdk=True),
            lambda s: s["device"]["props"].update(sdk="NaN"),
            lambda s: s["device"]["props"].update(sdk="0"),
            lambda s: s["device"]["props"].update(sdk="-1"),
            lambda s: s["device"]["props"].update(sdk="21.0"),
            lambda s: s["device"]["props"].update(sdk=21),
            lambda s: s["device"]["props"].update(sdk="2147483648"),
            lambda s: s["device"]["props"].update(sdk="２１"),
            lambda s: s["device"]["props"].pop("fingerprint"),
            lambda s: s["device"]["props"].update(model=None),
            lambda s: s["device"].update(selfProcInfo={"display": {"dpi": 420, "resolution": {"width": -1, "height": 100}}}),
        ]
        for mutation in mutations:
            snapshot, report = fixture()
            mutation(snapshot)
            with self.assertRaises(audit.Rejected):
                compare(snapshot, report)

    def test_allowlist_has_explicit_rule_or_unobservable_reason(self):
        for section, keys in audit.ALLOWED.items():
            for key in keys:
                if f"{section}.{key}" == "selfProcInfo.display":
                    continue
                self.assertIn(f"{section}.{key}", audit.RULES.keys() | audit.UNOBSERVABLE.keys())

    def test_cli_private_output_exit_codes_and_no_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot, report = fixture()
            snapshot_path, report_path, output = root / "snapshot.json", root / "report.json", root / "result.json"
            snapshot_path.write_text(json.dumps(snapshot))
            report_path.write_text(json.dumps(report))
            args = ["--snapshot", str(snapshot_path), "--report", str(report_path), "--expected-device-id", "running-ghost-id",
                    "--run-id", "test-run", "--not-before-ms", "1000", "--output", str(output)]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(0, audit.main(args))
            for secret in ("synthetic-account-sentinel", "TOKEN_SENTINEL", "PB_SENTINEL", "Test Device", "running-ghost-id"):
                self.assertNotIn(secret, stdout.getvalue())
                self.assertNotIn(secret, output.read_text())
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, audit.main(args), "existing output must not be overwritten")
            for expected_exit, change in [
                (1, lambda s: s["device"]["props"].update(model="OTHER")),
                (3, lambda s: s["device"].update(extraData={"ssaid_vending": "scope-value"})),
                (2, lambda s: s["device"].update(unknown_secret_key={"token": "SECRET"})),
            ]:
                changed = copy.deepcopy(snapshot)
                change(changed)
                snapshot_path.write_text(json.dumps(changed))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(expected_exit, audit.main(args[:-2]))
            snapshot_path.write_text('{"schema_version":3,"schema_version":3,"SECRET":')
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(2, audit.main(args[:-2]))
            self.assertNotIn("SECRET", stdout.getvalue())
            snapshot_path.write_text('{"schema_version":3,"schema_version":3}')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, audit.main(args[:-2]))


if __name__ == "__main__":
    unittest.main()
