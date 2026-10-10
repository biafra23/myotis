package io.myotis.desktop

import com.sun.jna.Callback
import com.sun.jna.CallbackReference
import com.sun.jna.Function
import com.sun.jna.Memory
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer

/** True on macOS, the one platform whose native APIs the desktop host calls directly. */
internal val isMacOs: Boolean get() = System.getProperty("os.name", "").lowercase().contains("mac")

/**
 * The Objective-C runtime entry points the desktop host calls through JNA ([AppNap],
 * [MacNotifications]). macOS only: [shared] throws elsewhere, as there is no libobjc to
 * load, and callers catch that.
 *
 * `objc_msgSend` is invoked with JNA's default, non-variadic convention, which is what
 * arm64 requires: the send trampoline jumps straight into the method with the caller's
 * registers, so every argument has to sit where the method's real prototype expects it.
 */
internal class ObjCRuntime private constructor() {
    companion object {
        /** The process-wide runtime, created on first use. Throws off macOS (and is retried then). */
        val shared: ObjCRuntime by lazy { ObjCRuntime() }
    }

    init {
        // NSString, NSBundle and NSProcessInfo live in Foundation: load it explicitly so the
        // classes resolve whatever the launch path happened to link (the jpackage launcher
        // is a Cocoa app; a bare test JVM is not).
        NativeLibrary.getInstance("Foundation")
    }

    private val objc = NativeLibrary.getInstance("objc")
    private val objcGetClass: Function = objc.getFunction("objc_getClass")
    private val selRegisterName: Function = objc.getFunction("sel_registerName")
    private val objcMsgSend: Function = objc.getFunction("objc_msgSend")
    private val poolPush: Function = objc.getFunction("objc_autoreleasePoolPush")
    private val poolPop: Function = objc.getFunction("objc_autoreleasePoolPop")

    /** Load a system framework (by name, e.g. "UserNotifications") so its classes resolve. */
    fun loadFramework(name: String) {
        NativeLibrary.getInstance(name)
    }

    /** Another libobjc entry point, for the rarer calls (defining a class at run time). */
    fun function(name: String): Function = objc.getFunction(name)

    fun cls(name: String): Pointer =
        objcGetClass.invokePointer(arrayOf(name)) ?: error("no Objective-C class $name")

    fun sel(name: String): Pointer = selRegisterName.invokePointer(arrayOf(name))

    fun send(receiver: Pointer?, selector: String, vararg args: Any?): Pointer? =
        objcMsgSend.invokePointer(arrayOf(receiver, sel(selector), *args))

    fun sendVoid(receiver: Pointer?, selector: String, vararg args: Any?) {
        objcMsgSend.invokeVoid(arrayOf(receiver, sel(selector), *args))
    }

    /** For methods returning NSInteger / NSUInteger. */
    fun sendLong(receiver: Pointer?, selector: String, vararg args: Any?): Long =
        objcMsgSend.invokeLong(arrayOf(receiver, sel(selector), *args))

    /** An autoreleased NSString holding [s], encoded as UTF-8 whatever the JVM's default charset. */
    fun nsString(s: String): Pointer {
        val utf8 = s.toByteArray(Charsets.UTF_8)
        val buf = Memory(utf8.size + 1L)
        buf.write(0, utf8, 0, utf8.size)
        buf.setByte(utf8.size.toLong(), 0)
        return send(cls("NSString"), "stringWithUTF8String:", buf) ?: error("NSString rejected the text")
    }

    /** The Kotlin string of an NSString; null for nil. */
    fun string(nsString: Pointer?): String? =
        nsString?.let { send(it, "UTF8String") }?.getString(0, "UTF-8")

    /**
     * Runs [block] inside an autorelease pool, so the autoreleased objects it creates are
     * freed when it returns: JVM threads have no pool of their own, and without one each
     * call would leak them.
     */
    fun <T> autoreleasePool(block: () -> T): T {
        val token = poolPush.invokePointer(emptyArray())
        try {
            return block()
        } finally {
            poolPop.invokeVoid(arrayOf(token))
        }
    }

    /**
     * Call a block an Objective-C API handed us (a completion handler): its invoke function
     * sits at offset 16 of the literal and takes the block itself first, then [args].
     */
    fun invokeBlock(block: Pointer, vararg args: Any?) {
        Function.getFunction(block.getPointer(16)).invokeVoid(arrayOf(block, *args))
    }
}

/**
 * A global Objective-C block literal whose invoke function is [callback]: what Cocoa APIs
 * take as a completion handler. Global, so the blocks runtime neither copies nor frees it,
 * and the API may call it from any thread, any number of times. It carries the type
 * [signature] a compiler-built block would, so code that inspects a block (forwarding it
 * over XPC, building an NSMethodSignature from it) finds what it expects. The literal, its
 * descriptor and the JNA trampoline behind [callback] stay alive as long as this object,
 * which its owner keeps for the life of the process.
 *
 * [signature] is the Objective-C type encoding of the block, e.g. `v16@?0@"NSError"8` for
 * `void (^)(NSError *)`: return type, frame size, then the block itself (`@?` at 0) and
 * each argument with its offset.
 */
internal class GlobalBlock(private val callback: Callback, signature: String) {
    private companion object {
        /** Block flags: no copy/dispose helpers, a global literal, a signature in the descriptor. */
        const val BLOCK_IS_GLOBAL = 1 shl 28
        const val BLOCK_HAS_SIGNATURE = 1 shl 30

        /** isa, flags, reserved, invoke, descriptor: 8 + 4 + 4 + 8 + 8 bytes in a 64-bit process. */
        const val LITERAL_SIZE = 32L
    }

    private val signatureText = Memory(signature.length + 1L).apply { setString(0, signature, "US-ASCII") }

    /** Descriptor: reserved, the literal's size, then (BLOCK_HAS_SIGNATURE) signature and layout. */
    private val descriptor = Memory(32).apply {
        setLong(0, 0)
        setLong(8, LITERAL_SIZE)
        setPointer(16, signatureText)
        setPointer(24, null)
    }

    val literal: Memory = Memory(LITERAL_SIZE).apply {
        setPointer(0, NativeLibrary.getInstance("System").getGlobalVariableAddress("_NSConcreteGlobalBlock"))
        setInt(8, BLOCK_IS_GLOBAL or BLOCK_HAS_SIGNATURE)
        setInt(12, 0)
        setPointer(16, CallbackReference.getFunctionPointer(callback))
        setPointer(24, descriptor)
    }
}
