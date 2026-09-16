package io.myotis.desktop

import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer

/**
 * Keeps macOS App Nap off for the life of the process.
 *
 * The desktop app serves JSON-RPC on localhost to OTHER processes (Bee, a wallet), and
 * macOS naps a GUI app whose window is hidden or fully covered: every thread drops to
 * the background scheduling band (kernel priority 4 — `ps -M -p <pid>` shows `4T`), and
 * on a busy host that turned the Bee PoC into an RPC endpoint that accepted connections
 * seconds late, spent 92 s in one Full GC and tripped Bee's 10-minute postage stall
 * (docs/bee-rpc-service.md, 2026-09-16). The `NSAppSleepDisabled` Info.plist key is
 * ignored by current macOS (measured on 15.7: a bundle carrying it naps exactly like
 * one without), so this uses Apple's in-process mechanism instead — an NSProcessInfo
 * activity held for the process lifetime — through JNA's Objective-C runtime calls.
 * Being in-process it also covers `:app-desktop:run` dev runs, which are a plain
 * `java` process with no bundle of their own.
 */
object AppNap {
    /**
     * NSActivityUserInitiatedAllowingIdleSystemSleep: the user-initiated class that
     * suspends App Nap, minus the bit that would keep the Mac from sleeping.
     */
    private const val USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP = 0x00EFFFFFL

    /** The activity token, retained and held forever so the activity never ends. */
    @Volatile
    private var activity: Pointer? = null

    val isMac: Boolean get() = System.getProperty("os.name", "").lowercase().contains("mac")

    /** True while the process holds the activity (macOS only). */
    val active: Boolean get() = activity != null

    /**
     * Begins the activity once (idempotent) and returns whether the process now holds
     * it. Never throws: on failure the app simply runs napped, as it did before, and
     * the caller logs that.
     */
    @Synchronized
    fun disable(reason: String): Boolean {
        if (activity != null) return true
        if (!isMac) return false
        return try {
            // NSProcessInfo and NSString live in Foundation: load it explicitly so the
            // classes resolve regardless of what the launch path happened to link (the
            // jpackage launcher is a Cocoa app; a bare test JVM is not).
            NativeLibrary.getInstance("Foundation")
            val objc = NativeLibrary.getInstance("objc")
            val objcGetClass = objc.getFunction("objc_getClass")
            val selRegisterName = objc.getFunction("sel_registerName")
            val objcMsgSend = objc.getFunction("objc_msgSend")
            fun cls(name: String): Pointer = objcGetClass.invokePointer(arrayOf(name))
            fun sel(name: String): Pointer = selRegisterName.invokePointer(arrayOf(name))
            val processInfo = objcMsgSend.invokePointer(arrayOf(cls("NSProcessInfo"), sel("processInfo")))
            val nsReason = objcMsgSend.invokePointer(arrayOf(cls("NSString"), sel("stringWithUTF8String:"), reason))
            val token: Pointer? = objcMsgSend.invokePointer(
                arrayOf(processInfo, sel("beginActivityWithOptions:reason:"), USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP, nsReason),
            )
            if (token == null) return false
            // The token comes back autoreleased; retain it so the activity outlives the pool.
            objcMsgSend.invokePointer(arrayOf(token, sel("retain")))
            activity = token
            true
        } catch (t: Throwable) { // UnsatisfiedLinkError, a missing JNA, anything from the runtime
            log.warn("App Nap could not be disabled — RPC may stall while the window is hidden: {}", t.toString())
            false
        }
    }

    // Lazy: the desktop logback config reads myotis.logdir when the first logger is created.
    private val log: org.slf4j.Logger by lazy { org.slf4j.LoggerFactory.getLogger(AppNap::class.java) }
}
