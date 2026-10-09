package io.myotis.desktop

import com.sun.jna.Function
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer

/**
 * Keeps macOS App Nap off while the user has not opted into it.
 *
 * The desktop app serves JSON-RPC on localhost to OTHER processes (Bee, a wallet), and
 * macOS naps a GUI app whose window is hidden or fully covered: every thread drops to
 * the background scheduling band (kernel priority 4 — `ps -M -p <pid>` shows `4T`), and
 * on a busy host that turned the Bee PoC into an RPC endpoint that accepted connections
 * seconds late, spent 92 s in one Full GC and tripped Bee's 10-minute postage stall
 * (docs/bee-rpc-service.md, 2026-09-16). The `NSAppSleepDisabled` Info.plist key is
 * ignored by current macOS (measured on 15.7: a bundle carrying it naps exactly like
 * one without), so this uses Apple's in-process mechanism instead — an NSProcessInfo
 * activity held for as long as napping is not allowed — through JNA's Objective-C
 * runtime calls. Being in-process it also covers `:app-desktop:run` dev runs, which are
 * a plain `java` process with no bundle of their own.
 *
 * Settings → Power → "Sleep when not in focus" is the opt-in: [disable] begins the
 * activity, [enable] ends it, and the desktop controller re-applies the persisted choice
 * at start and on every flip ([io.myotis.ui.NodeController.applyAppNap]).
 */
object AppNap {
    /** The reason macOS shows for the activity (`pmset -g assertions` and friends). */
    const val REASON = "Myotis serves JSON-RPC on localhost"

    /**
     * NSActivityUserInitiatedAllowingIdleSystemSleep: the user-initiated class that
     * suspends App Nap, minus the bit that would keep the Mac from sleeping.
     */
    private const val USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP = 0x00EFFFFFL

    /** The activity token, retained for as long as the activity is held. */
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
            val rt = ObjC()
            val nsReason = rt.send(rt.cls("NSString"), "stringWithUTF8String:", reason)
            val token: Pointer? = rt.send(
                rt.processInfo(), "beginActivityWithOptions:reason:", USER_INITIATED_ALLOWING_IDLE_SYSTEM_SLEEP, nsReason,
            )
            if (token == null) return false
            // The token comes back autoreleased; retain it so the activity outlives the pool.
            rt.send(token, "retain")
            activity = token
            true
        } catch (t: Throwable) { // UnsatisfiedLinkError, a missing JNA, anything from the runtime
            log.warn("App Nap could not be disabled — RPC may stall while the window is hidden: {}", t.toString())
            false
        }
    }

    /**
     * Ends the activity if one is held (idempotent) and returns whether the process
     * now holds none — i.e. whether macOS may nap it. Never throws: on failure the
     * activity stays held, which is the safe side, and the caller logs that.
     */
    @Synchronized
    fun enable(): Boolean {
        val token = activity ?: return true
        return try {
            val rt = ObjC()
            rt.sendVoid(rt.processInfo(), "endActivity:", token)
            rt.sendVoid(token, "release") // balances the retain in disable()
            activity = null
            true
        } catch (t: Throwable) {
            log.warn("App Nap could not be re-enabled — the no-nap activity stays held: {}", t.toString())
            false
        }
    }

    /** The three Objective-C runtime entry points the two calls above need. */
    private class ObjC {
        init {
            // NSProcessInfo and NSString live in Foundation: load it explicitly so the
            // classes resolve regardless of what the launch path happened to link (the
            // jpackage launcher is a Cocoa app; a bare test JVM is not).
            NativeLibrary.getInstance("Foundation")
        }
        private val objc = NativeLibrary.getInstance("objc")
        private val objcGetClass: Function = objc.getFunction("objc_getClass")
        private val selRegisterName: Function = objc.getFunction("sel_registerName")
        private val objcMsgSend: Function = objc.getFunction("objc_msgSend")

        fun cls(name: String): Pointer = objcGetClass.invokePointer(arrayOf(name))
        private fun sel(name: String): Pointer = selRegisterName.invokePointer(arrayOf(name))
        fun processInfo(): Pointer =
            send(cls("NSProcessInfo"), "processInfo") ?: error("NSProcessInfo.processInfo returned nil")
        fun send(receiver: Pointer, selector: String, vararg args: Any?): Pointer? =
            objcMsgSend.invokePointer(arrayOf(receiver, sel(selector), *args))
        fun sendVoid(receiver: Pointer, selector: String, vararg args: Any?) {
            objcMsgSend.invokeVoid(arrayOf(receiver, sel(selector), *args))
        }
    }

    // Lazy: the desktop logback config reads myotis.logdir when the first logger is created.
    private val log: org.slf4j.Logger by lazy { org.slf4j.LoggerFactory.getLogger(AppNap::class.java) }
}
