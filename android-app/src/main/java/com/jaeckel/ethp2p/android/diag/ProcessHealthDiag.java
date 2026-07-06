package com.jaeckel.ethp2p.android.diag;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Build;
import android.os.Debug;

import com.jaeckel.ethp2p.android.log.LogBuffer;

import java.util.List;

/**
 * On-device failure forensics for the Android node. The hypothesis under test is
 * WHY the light client didn't work on a real phone: OOM-kill (memory), CL catch-up
 * wedge, or the EL snap-peer pool never warming. None of those leaves an obvious
 * trace by default — an OOM-kill is a silent SIGKILL, and a wedge just looks like
 * "nothing happens" — so this makes each mode legible:
 *
 * <ul>
 *   <li>{@link #logLastExitReason} — on start, report HOW the previous process
 *       died ({@code ApplicationExitInfo}). {@code REASON_LOW_MEMORY} is the
 *       definitive "I was OOM-killed" signal; it also carries the PSS/RSS at death.
 *   <li>{@link #memorySummary} — the process's own PSS + JVM heap + the system's
 *       available memory / low-memory flag, for the periodic heartbeat.
 *   <li>{@link #trimLevelName} — decode an {@code onTrimMemory} level; the
 *       {@code RUNNING_CRITICAL}/{@code COMPLETE} levels are the "about to be
 *       killed" warning the system sends just before an OOM-kill.
 * </ul>
 *
 * All lines go through {@link LogBuffer} (tag {@code health}) so they land in the
 * in-app Logs tab AND logcat — capture either and send it over.
 */
public final class ProcessHealthDiag {

    public static final String TAG = "health";

    private ProcessHealthDiag() {}

    /**
     * Report how the previous process instance(s) exited — the single most useful
     * signal for "was it OOM-killed?". API 30+ (Pixel 7a is well past this); a no-op
     * with a note on older devices.
     */
    public static void logLastExitReason(Context ctx) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            LogBuffer.i(TAG, "exit-reason history needs Android 11+ (this device is API "
                    + Build.VERSION.SDK_INT + ") — rely on the live memory heartbeat instead");
            return;
        }
        try {
            ActivityManager am = ctx.getSystemService(ActivityManager.class);
            if (am == null) return;
            List<ApplicationExitInfo> infos =
                    am.getHistoricalProcessExitReasons(ctx.getPackageName(), 0, 5);
            if (infos == null || infos.isEmpty()) {
                LogBuffer.i(TAG, "no prior process-exit records (first run, or cleared)");
                return;
            }
            for (ApplicationExitInfo info : infos) {
                LogBuffer.i(TAG, "prior exit: " + describeReason(info.getReason())
                        + " status=" + info.getStatus()
                        + " importance=" + info.getImportance()
                        + " pssAtExit=" + kib(info.getPss())
                        + " rssAtExit=" + kib(info.getRss())
                        + " desc=" + info.getDescription());
            }
        } catch (Throwable t) {
            LogBuffer.i(TAG, "could not read exit-reason history: " + t);
        }
    }

    /** One-line memory summary for the heartbeat. Never throws. */
    public static String memorySummary(Context ctx) {
        StringBuilder sb = new StringBuilder();
        // Our own resident footprint — the number the low-memory killer scores.
        try {
            Debug.MemoryInfo mi = new Debug.MemoryInfo();
            Debug.getMemoryInfo(mi);
            sb.append("pss=").append(mib(mi.getTotalPss()));
            String nativeHeap = mi.getMemoryStat("summary.native-heap");
            String javaHeap = mi.getMemoryStat("summary.java-heap");
            if (javaHeap != null) sb.append(" jHeap=").append(mibStr(javaHeap));
            if (nativeHeap != null) sb.append(" nHeap=").append(mibStr(nativeHeap));
        } catch (Throwable t) {
            sb.append("pss=?");
        }
        // JVM heap headroom (an OutOfMemoryError vs an LMK-kill are different failures).
        try {
            Runtime rt = Runtime.getRuntime();
            long used = rt.totalMemory() - rt.freeMemory();
            sb.append(" jvmUsed=").append(mibB(used)).append("/").append(mibB(rt.maxMemory()));
        } catch (Throwable ignored) {
        }
        // System-wide pressure: is the phone itself low, and how close to the LMK threshold.
        try {
            ActivityManager am = ctx.getSystemService(ActivityManager.class);
            if (am != null) {
                ActivityManager.MemoryInfo mem = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(mem);
                sb.append(" sysAvail=").append(mibB(mem.availMem))
                        .append(" low=").append(mem.lowMemory)
                        .append(" lmkThreshold=").append(mibB(mem.threshold));
            }
        } catch (Throwable ignored) {
        }
        return sb.toString();
    }

    /** Human name for an onTrimMemory level. */
    public static String trimLevelName(int level) {
        switch (level) {
            case ComponentCallbacksLevels.RUNNING_MODERATE: return "RUNNING_MODERATE";
            case ComponentCallbacksLevels.RUNNING_LOW: return "RUNNING_LOW";
            case ComponentCallbacksLevels.RUNNING_CRITICAL: return "RUNNING_CRITICAL (near OOM-kill)";
            case ComponentCallbacksLevels.UI_HIDDEN: return "UI_HIDDEN";
            case ComponentCallbacksLevels.BACKGROUND: return "BACKGROUND";
            case ComponentCallbacksLevels.MODERATE: return "MODERATE";
            case ComponentCallbacksLevels.COMPLETE: return "COMPLETE (imminent kill)";
            default: return "level=" + level;
        }
    }

    private static String describeReason(int reason) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return "reason=" + reason;
        switch (reason) {
            case ApplicationExitInfo.REASON_LOW_MEMORY: return "LOW_MEMORY (OOM-killed)";
            case ApplicationExitInfo.REASON_CRASH: return "CRASH";
            case ApplicationExitInfo.REASON_CRASH_NATIVE: return "CRASH_NATIVE";
            case ApplicationExitInfo.REASON_ANR: return "ANR";
            case ApplicationExitInfo.REASON_SIGNALED: return "SIGNALED (killed)";
            case ApplicationExitInfo.REASON_USER_REQUESTED: return "USER_REQUESTED";
            case ApplicationExitInfo.REASON_EXIT_SELF: return "EXIT_SELF (clean stop)";
            case ApplicationExitInfo.REASON_DEPENDENCY_DIED: return "DEPENDENCY_DIED";
            case ApplicationExitInfo.REASON_OTHER: return "OTHER";
            case ApplicationExitInfo.REASON_UNKNOWN: return "UNKNOWN";
            default: return "reason=" + reason;
        }
    }

    // ---- formatting (KB inputs from Debug, byte inputs from Runtime/AM) ----

    private static String mib(int kib) { return (kib / 1024) + "MiB"; }
    private static String kib(long kib) { return kib + "KiB"; }
    private static String mibB(long bytes) { return (bytes / (1024 * 1024)) + "MiB"; }
    private static String mibStr(String kibStr) {
        try { return (Long.parseLong(kibStr.trim()) / 1024) + "MiB"; }
        catch (NumberFormatException e) { return kibStr; }
    }

    /** ComponentCallbacks2 level constants, inlined so callers needn't import it. */
    private static final class ComponentCallbacksLevels {
        static final int RUNNING_MODERATE = 5;
        static final int RUNNING_LOW = 10;
        static final int RUNNING_CRITICAL = 15;
        static final int UI_HIDDEN = 20;
        static final int BACKGROUND = 40;
        static final int MODERATE = 60;
        static final int COMPLETE = 80;
    }
}
