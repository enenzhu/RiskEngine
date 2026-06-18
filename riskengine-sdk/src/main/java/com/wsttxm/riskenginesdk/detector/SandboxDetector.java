package com.wsttxm.riskenginesdk.detector;

import android.app.ActivityManager;
import android.content.Context;

import com.wsttxm.riskenginesdk.model.DetectionResult;
import com.wsttxm.riskenginesdk.model.RiskLevel;
import com.wsttxm.riskenginesdk.util.CLog;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class SandboxDetector extends BaseDetector {

    public SandboxDetector(Context context) {
        super(context);
    }

    @Override
    public String getName() {
        return "sandbox";
    }

    @Override
    protected DetectionResult detect() {
        List<String> evidence = new ArrayList<>();

        checkProcessCount(evidence);
        checkFdCount(evidence);
        checkMultiUser(evidence);

        if (!evidence.isEmpty()) {
            return risk(RiskLevel.HIGH, String.join("; ", evidence));
        }
        return safe();
    }

    private void checkProcessCount(List<String> evidence) {
        // ⚠ Android 11+(API 30+)SELinux hardening 让非 root app 通过 /proc listFiles()
        // 只能看到自己的进程(1-5 个 dir)— /proc 全局视图被 hidepid=2 隔离。在普通
        // 应用上 < 50 一定命中,跟真假沙箱无关 = 必中误报。
        // 改用 ActivityManager.getRunningAppProcesses 拿当前 app 进程数(只是同 UID,
        // 但至少不会误报);对真沙箱 (VirtualApp/Parallel Space) 它们也走 fd 路径检测。
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            return; // Android 11+:/proc 视图不可信,跳过
        }
        try {
            File procDir = new File("/proc");
            File[] files = procDir.listFiles();
            int processCount = 0;
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) {
                        try {
                            Integer.parseInt(f.getName());
                            processCount++;
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            if (processCount > 0 && processCount < 50) {
                evidence.add("low_process_count:" + processCount);
            }
        } catch (Exception e) {
            CLog.e("Process count check failed", e);
        }
    }

    private void checkFdCount(List<String> evidence) {
        try {
            File fdDir = new File("/proc/self/fd");
            File[] fds = fdDir.listFiles();
            if (fds != null) {
                for (File fd : fds) {
                    try {
                        String link = fd.getCanonicalPath();
                        // 跳过系统组件路径 — Android 14+ SDK Runtime 的
                        // /apex/com.android.adservices/javalib/framework-sdksandbox.jar 名字
                        // 含 "sandbox" 字符串,真机也加载,不是多开/沙箱框架特征。
                        if (link.startsWith("/apex/") || link.startsWith("/system/")) continue;
                        // 多开框架特征路径:VirtualApp / Parallel Space / 双开
                        if (link.contains("virtual-app") ||
                                link.contains("/parallel/") || link.contains("ParallelSpace") ||
                                link.contains("/dual_") || link.contains("DualApp") ||
                                // 通用"sandbox"前后必须有路径/包名样式,避免命中系统 jar
                                link.matches(".*/[A-Za-z_]*sandbox[A-Za-z_]*/.*")) {
                            evidence.add("suspicious_fd:" + link);
                            break;
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            CLog.e("FD check failed", e);
        }
    }

    private void checkMultiUser(List<String> evidence) {
        try {
            int uid = android.os.Process.myUid();
            int userId = uid / 100000;
            if (userId != 0) {
                evidence.add("non_primary_user:" + userId);
            }
        } catch (Exception e) {
            CLog.e("Multi-user check failed", e);
        }
    }
}
