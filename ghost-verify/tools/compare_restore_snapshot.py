#!/usr/bin/env python3
"""Local schema3 restore audit. Never prints expected/observed values or account material."""
import argparse
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import struct


ALLOWED = {
    "props": set("manufacturer brand board device name model release sdk host fingerprint build_description baseband_version build_id bootloader version_incremental version_security_patch build_date_utc sku soc_model soc_manufacturer gpu serialno simOperator simOperatorName simCountryIso sim_imsi display_info sim_smsc sim_oc_name_id boot_vbmeta_digest config_ringtone boot_device hardware cpu_abi cpu_abi2 supported_32_bit_abis supported_64_bit_abis version_codename gl_vendor gl_version gl_version_code glsl_version gsf_android_id checkin_device_data_version_info".split()),
    "settingData": {"oaid", "brightness"},
    "selfProcInfo": set("timeZone locale localeStr display displayStr totalMemory diskSize densityDeviceStable runtimeTotal runtimeMax runtimeFree remainingDataPartitionSpace systemFeatures availableLocales".split()),
    "uname": set("sysname nodename release version machine".split()),
    "systemServerData": {"sensorMap"},
    "extraData": set("im me phone iccid carrier_id ssaid_vending disp_xdpi disp_ydpi cpu_count egle slibs vol_music vol_ring vol_alarm vol_notif vol_sys vol_vc".split()),
}
REQUIRED_BUILD = "manufacturer brand model fingerprint name device build_id release sdk".split()


class Rejected(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    field: str
    source: str
    layer: str = "java"
    kind: str = "text"


# The system rewrites these on its own schedule (auto-brightness), so a differing
# read after restore proves nothing; still observed and reported, never mismatched.
VOLATILE = {"settingData.brightness"}


BUILD_FIELDS = {
    "manufacturer": "MANUFACTURER", "brand": "BRAND", "board": "BOARD",
    "device": "DEVICE", "name": "PRODUCT", "model": "MODEL", "host": "HOST",
    "fingerprint": "FINGERPRINT", "build_id": "ID", "bootloader": "BOOTLOADER",
    "sku": "SKU", "soc_model": "SOC_MODEL", "soc_manufacturer": "SOC_MANUFACTURER",
}
RULES = {f"props.{key}": Rule(field, f"Build.{field}") for key, field in BUILD_FIELDS.items()}
for key, field in {"release": "RELEASE", "sdk": "SDK_INT", "version_incremental": "INCREMENTAL", "version_security_patch": "SECURITY_PATCH"}.items():
    RULES[f"props.{key}"] = Rule(field, f"Build.VERSION.{field}", kind="number" if key == "sdk" else "text")
RULES.update({
    "props.baseband_version": Rule("RADIO", "Build.RADIO"),
    "props.build_date_utc": Rule("TIME", "Build.TIME", kind="epoch_seconds"),
    "props.gpu": Rule("GL_RENDERER", "native EGL + glGetString", "native"),
    "props.serialno": Rule("SERIAL", "ro.serialno", "native"),
    "props.build_description": Rule("ro.build.description", "ro.build.description", "native"),
    "props.boot_vbmeta_digest": Rule("ro.boot.vbmeta.digest", "ro.boot.vbmeta.digest", "native"),
    # Ghost writes the canonical Android `soc/<node>.ufs` spelling; the producer's getprop may
    # lack the prefix on kernels that report the bare node.
    "props.boot_device": Rule("ro.boot.boot_devices", "ro.boot.boot_devices", "native", kind="boot_device"),
    "props.config_ringtone": Rule("ro.config.ringtone", "ro.config.ringtone", "native"),
    "settingData.brightness": Rule("SCREEN_BRIGHTNESS", "Settings.System", kind="number"),
    # AdvertisingIdClient appends " (limited=<bool>)"; the snapshot stores the bare ID.
    "settingData.oaid": Rule("GAID (Google Advertising ID)", "AdvertisingIdClient.Info.getId()", kind="gaid"),
    "extraData.slibs": Rule("restore.slibs", "PackageManager.getSystemSharedLibraryNames", kind="set"),
    "systemServerData.sensorMap": Rule("restore.sensorMap", "SensorManager.default_sensors", kind="sensor_map"),
    "selfProcInfo.timeZone": Rule("timezone", "TimeZone.getDefault().id"),
    "selfProcInfo.locale": Rule("restore.locale", "Resources.Configuration.locale", kind="locale"),
    "selfProcInfo.localeStr": Rule("restore.localeStr", "Resources.Configuration.locale"),
    "selfProcInfo.displayStr": Rule("resolution", "DisplayMetrics.{width,height}Pixels", kind="size"),
    "selfProcInfo.display.resolution.width": Rule("resolution", "DisplayMetrics.{width,height}Pixels", kind="width"),
    "selfProcInfo.display.resolution.height": Rule("resolution", "DisplayMetrics.{width,height}Pixels", kind="height"),
    "selfProcInfo.display.dpi": Rule("dpi_app_resources_java", "DisplayMetrics.densityDpi", kind="number"),
    "selfProcInfo.totalMemory": Rule("restore.total_memory_bytes", "ActivityManager.MemoryInfo.totalMem", kind="number"),
    "selfProcInfo.diskSize": Rule("restore.disk_bytes", "StatFs.external_storage.total_bytes", kind="number"),
    "extraData.disp_xdpi": Rule("restore.display.xdpi", "Display.getRealMetrics.xdpi", kind="number"),
    "extraData.disp_ydpi": Rule("restore.display.ydpi", "Display.getRealMetrics.ydpi", kind="number"),
    "extraData.cpu_count": Rule("cpu_count.available_processors", "Runtime.availableProcessors()", kind="number"),
    "props.version_codename": Rule("CODENAME", "Build.VERSION.CODENAME"),
    "props.gl_vendor": Rule("GL_VENDOR", "native EGL + glGetString", "native"),
    "props.gl_version": Rule("GL_VERSION", "native EGL + glGetString", "native"),
    "props.gsf_android_id": Rule("GSF Android ID", "gservices.android_id"),
})
for key in ("simOperator", "simOperatorName", "simCountryIso"):
    RULES[f"props.{key}"] = Rule(key, f"TelephonyManager.{key}")
for key in ALLOWED["uname"]:
    RULES[f"uname.{key}"] = Rule(f"uname.{key}", "native uname()", "native")

for stream, key in enumerate(("vol_vc", "vol_sys", "vol_ring", "vol_music", "vol_alarm", "vol_notif")):
    RULES[f"extraData.{key}"] = Rule(f"restore.{key}", f"AudioManager.getStreamVolume({stream})", kind="number")

# A different UID's SSAID is not this collector's ANDROID_ID. GAID is device/user scoped
# and is independently read via AdvertisingIdClient, never GMS private preferences/config.
UNOBSERVABLE = {
    "extraData.ssaid_vending": "cross_uid_ssaid_requires_play_observation",
    "props.hardware": "legacy_mapper_input_not_a_direct_live_restore_field",
    "props.sim_imsi": "privileged_subscription_identifier_not_sampled",
    "extraData.im": "privileged_slot_identifier_not_sampled",
    "extraData.me": "privileged_slot_identifier_not_sampled",
    "extraData.phone": "privileged_subscription_identifier_not_sampled",
    "extraData.iccid": "privileged_subscription_identifier_not_sampled",
    "props.display_info": "opaque_display_info_has_no_equivalent_observation",
    # The deployed observer reports only the merged SUPPORTED_ABIS list, not the per-ABI splits.
    "props.cpu_abi": "abi_reported_only_as_merged_supported_list",
    "props.cpu_abi2": "abi_reported_only_as_merged_supported_list",
    "props.supported_32_bit_abis": "observer_has_no_32_bit_split",
    "props.supported_64_bit_abis": "observer_has_no_64_bit_split",
    "props.gl_version_code": "req_gles_version_not_observed",
    "props.glsl_version": "glsl_not_hooked_by_producer_path",
    "props.checkin_device_data_version_info": "gms_private_preference_not_read_by_observer",
    "selfProcInfo.densityDeviceStable": "device_stable_density_not_separately_observed",
    "selfProcInfo.runtimeTotal": "jvm_heap_size_varies_with_launch",
    "selfProcInfo.runtimeMax": "jvm_heap_size_varies_with_launch",
    "selfProcInfo.runtimeFree": "jvm_free_heap_moves_constantly",
    "selfProcInfo.remainingDataPartitionSpace": "free_partition_space_moves_constantly",
    "selfProcInfo.systemFeatures": "observer_reports_count_and_hash_only",
    "selfProcInfo.availableLocales": "full_locale_inventory_not_observed",
    "props.sim_smsc": "smsc_not_sampled",
    "props.sim_oc_name_id": "carrier_name_id_not_sampled",
    "extraData.carrier_id": "carrier_id_not_sampled",
    "extraData.egle": "extension_length_or_hash_is_not_the_extension_set",
}


def require(condition, code):
    if not condition:
        raise Rejected(code)


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError("not_numeric")
    result = Decimal(str(value))
    if not result.is_finite():
        raise ValueError("not_finite")
    return result


def float32(value):
    return struct.unpack("f", struct.pack("f", float(value)))[0]


def normalize(value, kind, observed=False):
    if kind == "gaid":
        if not isinstance(value, str):
            raise ValueError("not_text")
        return value.partition(" (limited=")[0]
    if kind == "boot_device":
        if not isinstance(value, str) or not value.strip():
            raise ValueError("not_text")
        return re.sub(r"^soc/", "", value.strip())
    if kind in {"number", "epoch_seconds", "width", "height"}:
        if observed and kind in {"width", "height"}:
            dims = normalize(value, "size")
            return dims[0 if kind == "width" else 1]
        result = number(value)
        return result / 1000 if observed and kind == "epoch_seconds" else result
    if kind == "size":
        if not isinstance(value, str) or not re.fullmatch(r"\d+x\d+", value):
            raise ValueError("not_size")
        return tuple(sorted(int(part) for part in value.split("x")))
    if kind == "set":
        if not isinstance(value, str):
            raise ValueError("not_set")
        # RestoreDeviceCollector uses TextUtils.join(" ", libraries); the independent
        # GhostCollector observer uses joinToString(","). Both represent a name set.
        return set(value.split(",") if observed else value.split())
    if kind == "sensor_map":
        obj = json.loads(value) if observed else value
        if not isinstance(obj, dict):
            raise ValueError("not_sensor_map")
        for key, sensor in obj.items():
            if not key.isdigit() or not isinstance(sensor, dict) or set(sensor) != {"name", "vendor", "maxRange", "resolution"}:
                raise ValueError("not_sensor_map")
            if not isinstance(sensor["name"], str) or not isinstance(sensor["vendor"], str):
                raise ValueError("not_sensor_map")
            number(sensor["maxRange"])
            number(sensor["resolution"])
            # SensorManager stores these as float32; JSON may spell the same value with the
            # producer's long expansion or the observer's short form.
            for measure in ("maxRange", "resolution"):
                sensor[measure] = float32(sensor[measure])
        return obj
    if kind == "locale":
        obj = json.loads(value) if observed else value
        if not isinstance(obj, dict) or set(obj) - {"script"} != {"language", "country", "variant"}:
            raise ValueError("not_locale")
        if not all(isinstance(item, str) for item in obj.values()):
            raise ValueError("not_locale")
        # The deployed observer predates the snapshot's optional `script`; compare the trio only.
        return {key: obj[key] for key in ("language", "country", "variant")}
    if not isinstance(value, str):
        raise ValueError("not_text")
    return value  # Build, identifiers and timezone IDs are case-sensitive.


def expected_fields(snapshot):
    if isinstance(snapshot, dict) and "schema_version" not in snapshot:
        data = snapshot.get("data")
        require(isinstance(data, dict) and "clone_data" in data, "schema3_snapshot_required")
        snapshot = data["clone_data"]
        if isinstance(snapshot, str):
            snapshot = decode(snapshot)
    require(isinstance(snapshot, dict) and type(snapshot.get("schema_version")) is int and snapshot["schema_version"] == 3,
            "schema3_snapshot_required")
    device = snapshot.get("device")
    require(isinstance(device, dict) and bool(device), "canonical_device_required")
    require(not set(device) - set(ALLOWED), "unknown_device_section")
    props = device.get("props", {})
    require(isinstance(props, dict), "invalid_props")
    require(all(isinstance(props.get(key), str) and props[key].strip() for key in REQUIRED_BUILD if key != "sdk"),
            "required_build_missing")
    # Service schema3 requires ASCII decimal text; RestoreDeviceFields.legacyDevice
    # consumes a positive Kotlin Int. Neither bounds supported Android generations
    # nor requires a known SDK/release pair (the standalone producer supports API21).
    sdk = props.get("sdk")
    require(isinstance(sdk, str) and re.fullmatch(r"[0-9]+", sdk) is not None, "invalid_sdk")
    require(0 < int(sdk) <= 2147483647, "invalid_sdk")
    result = {}
    for section, values in device.items():
        require(isinstance(values, dict), "invalid_device_section")
        require(not set(values) - ALLOWED[section], "unknown_device_field")
        for key, value in values.items():
            path = f"{section}.{key}"
            require(value is not None, "null_canonical_field")
            if path == "selfProcInfo.display":
                require(isinstance(value, dict) and set(value) == {"resolution", "dpi"}, "invalid_display")
                resolution = value["resolution"]
                require(isinstance(resolution, dict) and set(resolution) == {"width", "height"}, "invalid_resolution")
                require(all(type(v) is int and v > 0 for v in (*resolution.values(), value["dpi"])), "invalid_display")
                width, height = sorted(resolution.values())
                result.update({f"{path}.resolution.width": width, f"{path}.resolution.height": height, f"{path}.dpi": value["dpi"]})
            else:
                result[path] = value
    return result


def report_fields(report, run_id, restored_device_id, not_before_ms):
    require(isinstance(report, dict), "collection_report_required")
    meta = report.get("_meta")
    require(isinstance(meta, dict), "collection_metadata_required")
    audit = meta.get("restore_audit")
    require(isinstance(audit, dict) and type(audit.get("schemaVersion")) is int and audit["schemaVersion"] == 1,
            "fresh_restore_audit_required")
    require(audit.get("dataKind") == "live", "live_collection_required")
    require(audit.get("runId") == run_id and bool(run_id), "collection_run_mismatch")
    start, end = audit.get("startedAt"), audit.get("completedAt")
    require(type(start) is int and type(end) is int and 0 < not_before_ms <= start <= end, "collection_time_invalid")
    for name in ("before", "after"):
        state = audit.get(name)
        require(isinstance(state, dict) and state.get("status") == "ok", "identity_evidence_unavailable")
        require(state.get("adopted") is True, "collector_not_adopted")
        require(state.get("deviceId") == restored_device_id and bool(restored_device_id), "running_identity_mismatch")
    ghost = report.get("ghost")
    require(isinstance(ghost, dict), "actual_collection_required")
    timestamp = ghost.get("timestamp")
    require(type(timestamp) is int and start <= timestamp <= end, "collection_time_invalid")
    context = ghost.get("observationContext")
    require(isinstance(context, dict) and context.get("packageName") == "com.ghost.verify" and
            context.get("processName") == "com.ghost.verify" and context.get("scope") == "collector_process_and_children" and
            type(context.get("uid")) is int and context["uid"] >= 10000 and
            type(context.get("pid")) is int and context["pid"] > 0, "collector_scope_invalid")
    fields = ghost.get("fields")
    require(isinstance(fields, list) and bool(fields) and ghost.get("fieldCount") == len(fields), "actual_fields_required")
    result = {}
    for field in fields:
        require(isinstance(field, dict) and isinstance(field.get("name"), str) and field["name"] not in result,
                "invalid_or_duplicate_field")
        sources = field.get("sources")
        require(isinstance(sources, list), "invalid_sources")
        source_keys = set()
        for source in sources:
            require(isinstance(source, dict) and isinstance(source.get("source"), str) and isinstance(source.get("layer"), str),
                    "invalid_source")
            key = source["source"], source["layer"]
            require(key not in source_keys, "duplicate_source")
            source_keys.add(key)
        result[field["name"]] = field
    return result


def compare(snapshot, report, *, run_id, restored_device_id, not_before_ms):
    expected = expected_fields(snapshot)
    observed = report_fields(report, run_id, restored_device_id, not_before_ms)
    rows = []
    for path, value in sorted(expected.items()):
        row = {"field": path}
        if path in UNOBSERVABLE:
            row.update(status="UNOBSERVABLE", reason=UNOBSERVABLE[path])
        else:
            rule = RULES[path]
            try:
                want = normalize(value, rule.kind)
            except (ValueError, TypeError, InvalidOperation):
                raise Rejected("invalid_canonical_value") from None
            field = observed.get(rule.field)
            source = next((s for s in field["sources"] if s["source"] == rule.source and s["layer"] == rule.layer), None) if field else None
            row.update(observedField=rule.field, source=rule.source, layer=rule.layer)
            if source is None:
                row.update(status="MISSING", reason="direct_observation_missing")
            elif source.get("error") or source.get("value") is None or (
                    source.get("value") == "" and path != "props.baseband_version"):
                row.update(status="UNOBSERVABLE", reason="direct_api_failed_or_unavailable")
            elif not isinstance(source["value"], str):
                row.update(status="UNOBSERVABLE", reason="invalid_observation_type")
            elif source["value"].strip().lower() in {"unknown", "null", "unavailable", "-1", "00000000-0000-0000-0000-000000000000"} or source["value"].lstrip().startswith("<"):
                row.update(status="UNOBSERVABLE", reason="placeholder_or_permission_denied")
            else:
                try:
                    actual = normalize(source["value"], rule.kind, observed=True)
                except (ValueError, TypeError, InvalidOperation):
                    row.update(status="UNOBSERVABLE", reason="invalid_observation_value")
                else:
                    if path in VOLATILE:
                        row.update(status="UNOBSERVABLE", reason="known_volatile_value")
                    else:
                        row.update(status="PASS" if actual == want else "MISMATCH", reason="direct_api_comparison")
        rows.append(row)
    counts = Counter(row["status"] for row in rows)
    total = len(rows)
    sampled = counts["PASS"] + counts["MISMATCH"]
    require(sampled > 0, "no_actual_observations")
    verdict = "FAIL" if counts["MISSING"] or counts["MISMATCH"] else "PARTIAL" if counts["UNOBSERVABLE"] else "PASS"
    return {
        "verdict": verdict,
        "coverage": {"total": total, "observed": sampled, "pass": counts["PASS"], "mismatch": counts["MISMATCH"],
                     "missing": counts["MISSING"], "unobservable": counts["UNOBSERVABLE"],
                     "observedPercent": round(100 * sampled / total, 2), "passPercent": round(100 * counts["PASS"] / total, 2)},
        "fields": rows,
    }


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(text):
    def invalid_constant(_):
        raise Rejected("invalid_json_number")
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def load(path):
    return decode(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, help="decrypted schema3 snapshot, local/private only")
    parser.add_argument("--report", required=True, help="fresh auto=restore-audit report")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-device-id", "--restored-device-id", dest="restored_device_id", required=True,
                        help="Ghost current running device ID; NOT source GSF snapshot device_id")
    parser.add_argument("--not-before-ms", type=int, required=True, help="device epoch milliseconds captured before launch")
    parser.add_argument("--output", help="sanitized JSON result; creates a new file with mode 0600, never overwrites")
    args = parser.parse_args(argv)
    try:
        result = compare(load(args.snapshot), load(args.report), run_id=args.run_id,
                         restored_device_id=args.restored_device_id, not_before_ms=args.not_before_ms)
    except (Rejected, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        # Never echo JSON decoder fragments, filenames, unknown keys or input values.
        code = str(error) if isinstance(error, Rejected) else "invalid_or_unreadable_input"
        result = {"verdict": "REJECTED", "reason": code}
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        try:
            with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as output:
                output.write(text + "\n")
        except OSError:
            print(json.dumps({"verdict": "REJECTED", "reason": "output_unwritable_or_exists"}))
            return 2
    print(text)
    return {"PASS": 0, "FAIL": 1, "PARTIAL": 3, "REJECTED": 2}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
