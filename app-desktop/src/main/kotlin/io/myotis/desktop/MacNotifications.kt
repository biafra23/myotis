package io.myotis.desktop

import com.sun.jna.Callback
import com.sun.jna.Pointer

/**
 * Native notifications on macOS through UserNotifications (`UNUserNotificationCenter`),
 * the API macOS lists an app under in System Settings → Notifications.
 *
 * Why not the tray icon, which carries them elsewhere: Compose's `TrayState.sendNotification`
 * ends in AWT's `TrayIcon.displayMessage`, which on macOS posts through
 * `NSUserNotificationCenter`, deprecated since macOS 11. From the packaged app that route
 * neither showed the refused-web-page notification (#610) nor put Myotis in System
 * Settings → Notifications (reported 2026-10-10). `UNUserNotificationCenter` lists the app
 * as soon as it asks for permission, which [start] does: macOS prompts once, stores the
 * answer and never prompts again. Notifications then carry the app's own name and icon.
 * jpackage's ad-hoc signature is enough; macOS keys the permission to the bundle id.
 *
 * Packaged app only. `currentNotificationCenter` raises an Objective-C exception, which
 * aborts the JVM since nothing between it and JNA can catch it, when LaunchServices has
 * no bundle record for the process, as for `:app-desktop:run` and a test JVM (a plain
 * `java` from a JDK). So [start] runs after the window exists, when NSApplication has
 * finished launching, and asks LaunchServices the same question first
 * (`LSBundleProxy bundleProxyForCurrentProcess`, the call whose nil the exception reports).
 * Anywhere that answer is not a yes, the tray route stays.
 *
 * A small delegate makes macOS show the banner while Myotis is the frontmost app too
 * (by default it would only file it in Notification Center), since the window may be on
 * a tab other than Status.
 */
internal object MacNotifications {
    private const val OPTION_SOUND = 1L shl 1
    private const val OPTION_ALERT = 1L shl 2

    /** UNNotificationPresentationOptions: banner, list and sound, for a notification posted in front. */
    private const val PRESENT_IN_FRONT = (1L shl 4) or (1L shl 3) or (1L shl 1)

    /** UNErrorCodeNotificationsNotAllowed in UNErrorDomain: the app may not post. */
    private const val ERROR_DOMAIN = "UNErrorDomain"
    private const val ERROR_NOT_ALLOWED = 1L

    /** [appName]: the bundle's name, which System Settings → Notifications lists it under. */
    private class Setup(val rt: ObjCRuntime, val center: Pointer, val appName: String)

    /** Null wherever UserNotifications may not be used; see the class doc. */
    private val setup: Setup? by lazy { setUp() }

    /** The answer to the permission request: null until it arrives. */
    @Volatile
    private var permission: Boolean? = null

    /** Set once a post was refused for want of permission, so that is logged once until it changes. */
    @Volatile
    private var notAllowedLogged = false

    /**
     * Set up UserNotifications and ask for permission to post banners with sound. The
     * first ask in an install shows macOS's prompt and lists the app in System Settings →
     * Notifications; later asks return the stored answer silently, and the answer is
     * logged. True when [post] can be used. Call once, after the window exists; never throws.
     */
    fun start(): Boolean {
        val s = setup ?: return false
        try {
            s.rt.autoreleasePool {
                s.rt.sendVoid(
                    s.center, "requestAuthorizationWithOptions:completionHandler:",
                    OPTION_ALERT or OPTION_SOUND, authorizationBlock.literal,
                )
            }
        } catch (t: Throwable) {
            log.warn("macOS notifications: the permission request failed: {}", t.toString())
        }
        return true
    }

    private fun setUp(): Setup? {
        if (!isMacOs) return null
        return try {
            val rt = ObjCRuntime.shared
            rt.loadFramework("CoreServices")
            rt.loadFramework("UserNotifications")
            rt.autoreleasePool {
                val bundle = rt.send(rt.cls("NSBundle"), "mainBundle")
                val path = rt.string(rt.send(bundle, "bundlePath"))
                when {
                    path == null || !path.endsWith(".app") || rt.send(bundle, "bundleIdentifier") == null -> {
                        log.info("macOS notifications: not running from an app bundle ({}), so they go through the tray icon", path)
                        null
                    }
                    !launchServicesKnowsThisProcess(rt) -> {
                        log.warn("macOS notifications: LaunchServices has no record of {}, so they go through the tray icon", path)
                        null
                    }
                    else -> {
                        val center = rt.send(rt.cls("UNUserNotificationCenter"), "currentNotificationCenter")
                            ?: error("UNUserNotificationCenter.currentNotificationCenter returned nil")
                        // The center keeps its delegate weakly; ours is never released.
                        rt.sendVoid(center, "setDelegate:", foregroundDelegate)
                        Setup(rt, center, appName = path.substringAfterLast('/').removeSuffix(".app"))
                    }
                }
            }
        } catch (t: Throwable) { // UnsatisfiedLinkError, a missing JNA, a missing class
            log.warn("macOS notifications unavailable, using the tray icon: {}", t.toString())
            null
        }
    }

    /**
     * `+[LSBundleProxy bundleProxyForCurrentProcess]` is not nil: the question whose "no" makes
     * `currentNotificationCenter` raise. LSBundleProxy is private, so its method is probed
     * first with `class_getClassMethod`, plain C that cannot raise. Sending a selector a
     * future macOS no longer has would raise `NSInvalidArgumentException` instead, which
     * aborts the JVM like the exception this guards against. A missing class throws a Kotlin
     * error from [ObjCRuntime.cls], which the caller catches. Either way, anything but a
     * yes keeps the tray route.
     */
    private fun launchServicesKnowsThisProcess(rt: ObjCRuntime): Boolean {
        val proxy = rt.cls("LSBundleProxy")
        val method = rt.function("class_getClassMethod").invokePointer(arrayOf(proxy, rt.sel("bundleProxyForCurrentProcess")))
        return method != null && rt.send(proxy, "bundleProxyForCurrentProcess") != null
    }

    /**
     * Post [title] / [body] now. True when macOS has granted permission, as far as this
     * run knows: the request is submitted either way, and a refusal is logged when macOS
     * reports it. False wherever [start] is not. Never throws.
     */
    @Synchronized
    fun post(title: String, body: String): Boolean {
        val s = setup ?: return false
        val rt = s.rt
        return try {
            rt.autoreleasePool {
                val content = rt.send(rt.send(rt.cls("UNMutableNotificationContent"), "alloc"), "init")
                    ?: error("UNMutableNotificationContent init returned nil")
                try {
                    rt.sendVoid(content, "setTitle:", rt.nsString(title))
                    rt.sendVoid(content, "setBody:", rt.nsString(body))
                    rt.sendVoid(content, "setSound:", rt.send(rt.cls("UNNotificationSound"), "defaultSound"))
                    val request = rt.send(
                        rt.cls("UNNotificationRequest"), "requestWithIdentifier:content:trigger:",
                        rt.nsString("myotis-" + java.util.UUID.randomUUID()), content, null, // nil trigger: now
                    ) ?: error("UNNotificationRequest returned nil")
                    rt.sendVoid(s.center, "addNotificationRequest:withCompletionHandler:", request, deliveryBlock.literal)
                } finally {
                    rt.sendVoid(content, "release") // the request holds its own reference
                }
            }
            permission == true
        } catch (t: Throwable) {
            log.warn("macOS notification could not be posted: {}", t.toString())
            false
        }
    }

    /** Where the user turns this app's notifications on: a PoC build is listed under its own name. */
    private fun settingsPath() = "System Settings → Notifications → ${setup?.appName ?: "Myotis"}"

    /** Domain, code and description of an NSError, for the log. */
    private fun describe(rt: ObjCRuntime, error: Pointer): String = rt.autoreleasePool {
        "${rt.string(rt.send(error, "domain"))} ${rt.sendLong(error, "code")}: " +
            "${rt.string(rt.send(error, "localizedDescription"))}"
    }

    // ---- completion handlers: Objective-C blocks backed by JNA callbacks ----

    private val onAuthorization = object : AuthorizationCallback {
        override fun invoke(block: Pointer?, granted: Byte, error: Pointer?) {
            runCatching {
                val rt = setup?.rt ?: return@runCatching
                when {
                    error != null -> log.warn("macOS notifications: permission request failed ({})", describe(rt, error))
                    granted.toInt() != 0 -> {
                        permission = true
                        notAllowedLogged = false
                        log.info("macOS notifications: allowed")
                    }
                    else -> {
                        permission = false
                        log.warn("macOS notifications: not allowed, so refused web pages show in the app's window " +
                            "only (turn them on in {})", settingsPath())
                    }
                }
            } // never throw into the caller's dispatch queue
        }
    }

    private val onDelivery = object : DeliveryCallback {
        override fun invoke(block: Pointer?, error: Pointer?) {
            runCatching {
                if (error == null) { // shown: permission holds, whatever was known before
                    permission = true
                    notAllowedLogged = false
                    return@runCatching
                }
                val rt = setup?.rt ?: return@runCatching
                val notAllowed = rt.autoreleasePool {
                    rt.string(rt.send(error, "domain")) == ERROR_DOMAIN && rt.sendLong(error, "code") == ERROR_NOT_ALLOWED
                }
                if (!notAllowed) {
                    log.warn("macOS notification not shown ({})", describe(rt, error))
                } else if (!notAllowedLogged) {
                    notAllowedLogged = true
                    if (permission == null) {
                        log.warn("macOS notification not shown: the permission prompt is not answered yet")
                    } else {
                        log.warn("macOS notification not shown: notifications are turned off in {}", settingsPath())
                        permission = false // turned off since the start, if it was on
                    }
                }
            }
        }
    }

    private val isArm64 = System.getProperty("os.arch", "").let { it == "aarch64" || it == "arm64" }

    // BOOL is a C bool ("B") on arm64 and a signed char ("c") on x86_64.
    private val authorizationBlock by lazy {
        GlobalBlock(onAuthorization, if (isArm64) "v20@?0B8@\"NSError\"12" else "v20@?0c8@\"NSError\"12")
    }
    private val deliveryBlock by lazy { GlobalBlock(onDelivery, "v16@?0@\"NSError\"8") }

    // ---- the delegate that presents notifications while the app is in front ----

    private val onWillPresent = object : WillPresentCallback {
        override fun invoke(self: Pointer?, cmd: Pointer?, center: Pointer?, notification: Pointer?, completionHandler: Pointer?) {
            runCatching {
                if (completionHandler != null) ObjCRuntime.shared.invokeBlock(completionHandler, PRESENT_IN_FRONT)
            }
        }
    }

    /**
     * An instance of a class defined at run time that implements the one
     * `UNUserNotificationCenterDelegate` method that matters here,
     * `userNotificationCenter:willPresentNotification:withCompletionHandler:`, answering
     * banner, list and sound. Created once per process: a class name registers once.
     */
    internal val foregroundDelegate: Pointer by lazy {
        val rt = ObjCRuntime.shared
        val cls = rt.function("objc_allocateClassPair")
            .invokePointer(arrayOf(rt.cls("NSObject"), "MyotisNotificationPresenter", 0L))
            ?: error("could not define the notification delegate class")
        // BOOL results are read as a byte: narrower than an int, its upper register bits are not defined.
        val added = rt.function("class_addMethod").invoke(Byte::class.javaObjectType, arrayOf(
            cls, rt.sel("userNotificationCenter:willPresentNotification:withCompletionHandler:"),
            onWillPresent, "v@:@@@?",
        )) as Byte
        if (added.toInt() == 0) error("could not add the willPresent method")
        // Conformance is declared for completeness: the center asks respondsToSelector:.
        rt.function("objc_getProtocol").invokePointer(arrayOf("UNUserNotificationCenterDelegate"))?.let {
            rt.function("class_addProtocol").invokeVoid(arrayOf(cls, it))
        }
        rt.function("objc_registerClassPair").invokeVoid(arrayOf(cls))
        rt.send(rt.send(cls, "alloc"), "init") ?: error("the notification delegate did not initialise")
    }

    // Lazy: the desktop logback config reads myotis.logdir when the first logger is created.
    private val log: org.slf4j.Logger by lazy { org.slf4j.LoggerFactory.getLogger(MacNotifications::class.java) }
}

/** `void (^)(BOOL granted, NSError *error)`, the handler of requestAuthorization. */
internal fun interface AuthorizationCallback : Callback {
    fun invoke(block: Pointer?, granted: Byte, error: Pointer?)
}

/** `void (^)(NSError *error)`, the handler of addNotificationRequest. */
internal fun interface DeliveryCallback : Callback {
    fun invoke(block: Pointer?, error: Pointer?)
}

/** The IMP of `userNotificationCenter:willPresentNotification:withCompletionHandler:`. */
internal fun interface WillPresentCallback : Callback {
    fun invoke(self: Pointer?, cmd: Pointer?, center: Pointer?, notification: Pointer?, completionHandler: Pointer?)
}
