package com.wsttxm.riskenginesdk.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class CollectorResult {
    private final String fieldName;
    private final Map<String, String> values;
    private boolean consistent;
    private String canonicalValue;
    private final long timestampMs;

    public CollectorResult(String fieldName) {
        this.fieldName = fieldName;
        this.values = new LinkedHashMap<>();
        this.timestampMs = System.currentTimeMillis();
        this.consistent = true;
    }

    public void addValue(String method, String value) {
        values.put(method, value);
        if (canonicalValue == null && value != null && !value.isEmpty()) {
            canonicalValue = value;
        }
    }

    /**
     * 跨源一致性比对 — 仅用于 method 全是"同一字段不同 source"的场景
     * (eg build_props 里同时有 java/native/shell 三 source 比对 ro.build.fingerprint)。
     *
     * 历史 bug:之前 addValue 自动调 updateConsistency,把 values map 里所有值
     * 当作"应一致的同字段多源",但实际多数 collector 塞的是异构字段
     * (wifi_info 里 mac_address/ssid/bssid/ip 6 个不同 sub-field),必报
     * inconsistent → multi_source_validation 100% 误报。
     *
     * 现改成"显式 opt-in":collector 若真的有跨源比对需求,addValue 完后
     * 主动 markCrossSourceConsistency()。默认 consistent=true 不做 equality。
     */
    public void markCrossSourceConsistency() {
        if (values.size() < 2) { consistent = true; return; }
        String first = null;
        consistent = true;
        for (String v : values.values()) {
            if (v == null || v.isEmpty()) continue;
            if (first == null) first = v;
            else if (!first.equals(v)) { consistent = false; break; }
        }
    }

    public String getFieldName() { return fieldName; }
    public Map<String, String> getValues() { return values; }
    public boolean isConsistent() { return consistent; }
    public String getCanonicalValue() { return canonicalValue; }
    public long getTimestampMs() { return timestampMs; }
}
