package io.myotis.ios

import platform.Foundation.NSNotificationCenter
import platform.Foundation.NSOperationQueue
import platform.UIKit.UIApplication
import platform.UIKit.UIApplicationDidEnterBackgroundNotification
import platform.UIKit.UIApplicationWillEnterForegroundNotification
import platform.UIKit.UIBackgroundTaskIdentifier
import platform.UIKit.UIBackgroundTaskInvalid

/**
 * Stretches the app's life a little past backgrounding: on didEnterBackground
 * it requests a UIKit background task, which keeps the process (engine + the
 * JSON-RPC listener) running for the system-granted grace — typically ~30 s —
 * so an in-flight wallet call or a final sync step can finish instead of being
 * frozen mid-request. The task ends on the expiration handler (mandatory —
 * overrunning it is a watchdog kill) or when the app returns to the foreground.
 *
 * This is deliberately NOT a background *mode*: after the grace the app
 * suspends normally, per the from-day-one assumption that iOS kills/suspends
 * the app in background and the node simply resumes on next launch.
 */
object IosBackgroundKeepalive {

    private var task: UIBackgroundTaskIdentifier = UIBackgroundTaskInvalid

    fun install() {
        val center = NSNotificationCenter.defaultCenter
        center.addObserverForName(
            UIApplicationDidEnterBackgroundNotification, null, NSOperationQueue.mainQueue,
        ) { _ ->
            begin()
        }
        center.addObserverForName(
            UIApplicationWillEnterForegroundNotification, null, NSOperationQueue.mainQueue,
        ) { _ ->
            end()
        }
    }

    private fun begin() {
        if (task != UIBackgroundTaskInvalid) return
        task = UIApplication.sharedApplication.beginBackgroundTaskWithName("myotis-rpc-grace") {
            // Expiration: the grace is up — end the task promptly (the engine and
            // listener simply freeze with the process; nothing to tear down).
            end()
        }
    }

    private fun end() {
        val t = task
        if (t == UIBackgroundTaskInvalid) return
        task = UIBackgroundTaskInvalid
        UIApplication.sharedApplication.endBackgroundTask(t)
    }
}
