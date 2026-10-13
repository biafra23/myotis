package io.myotis.desktop

import com.sun.jna.Callback
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class ObjCRuntimeTest {
    /** `void (^)(void)`: what NSBlockOperation runs. */
    fun interface VoidBlockCallback : Callback {
        fun invoke(block: Pointer?)
    }

    /** `void (^)(NSUInteger)`: the shape of the delegate's completion handler. */
    fun interface OptionsCallback : Callback {
        fun invoke(block: Pointer?, options: Long)
    }

    private fun macOnly() = assumeTrue(isMacOs, "macOS only: the Objective-C runtime is what is under test")

    @Test
    fun `round-trips UTF-8 text through NSString`() {
        macOnly()
        val rt = ObjCRuntime.shared
        val text = "Myotis — Jäckel 🦇"
        assertEquals(text, rt.autoreleasePool { rt.string(rt.nsString(text)) })
    }

    @Test
    fun `a GlobalBlock is a block Foundation can call`() {
        macOnly()
        val rt = ObjCRuntime.shared
        var calls = 0
        var seen = 0L
        val block = GlobalBlock(object : VoidBlockCallback {
            override fun invoke(block: Pointer?) {
                calls++
                seen = Pointer.nativeValue(block)
            }
        }, "v8@?0")
        rt.autoreleasePool {
            val op = rt.send(rt.cls("NSBlockOperation"), "blockOperationWithBlock:", block.literal)
            rt.sendVoid(op, "start") // a non-concurrent operation runs its block on this thread
        }
        assertEquals(1, calls)
        // A global block is never copied: the runtime calls the literal itself.
        assertEquals(Pointer.nativeValue(block.literal), seen)
    }

    @Test
    fun `a GlobalBlock carries a signature the blocks runtime and Foundation read`() {
        macOnly()
        val rt = ObjCRuntime.shared
        val signature = "v20@?0B8@\"NSError\"12" // void (^)(BOOL, NSError *)
        val block = GlobalBlock(object : VoidBlockCallback {
            override fun invoke(block: Pointer?) = Unit
        }, signature)
        val read = NativeLibrary.getInstance("System").getFunction("_Block_signature")
            .invokePointer(arrayOf(block.literal))?.getString(0, "US-ASCII")
        assertEquals(signature, read)
        val arguments = rt.autoreleasePool {
            rt.sendLong(rt.send(rt.cls("NSMethodSignature"), "signatureWithObjCTypes:", read), "numberOfArguments")
        }
        assertEquals(3L, arguments) // the block itself, the BOOL, the NSError
    }

    @Test
    fun `the notification delegate presents banner, list and sound`() {
        macOnly()
        var presented = -1L
        val handler = GlobalBlock(object : OptionsCallback {
            override fun invoke(block: Pointer?, options: Long) {
                presented = options
            }
        }, "v16@?0Q8")
        ObjCRuntime.shared.sendVoid(
            MacNotifications.foregroundDelegate,
            "userNotificationCenter:willPresentNotification:withCompletionHandler:",
            null, null, handler.literal,
        )
        assertEquals((1L shl 4) or (1L shl 3) or (1L shl 1), presented) // banner, list, sound
    }
}
