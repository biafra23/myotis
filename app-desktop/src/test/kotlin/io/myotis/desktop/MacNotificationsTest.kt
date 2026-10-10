package io.myotis.desktop

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class MacNotificationsTest {
    @Test
    fun `stays off outside an app bundle`() {
        // A test JVM is a plain `java` on every OS: exactly the process UNUserNotificationCenter
        // must never be asked about, as it would abort the JVM. On macOS this walks the
        // NSBundle check through the Objective-C runtime for real.
        assertFalse(MacNotifications.start())
        assertFalse(MacNotifications.post("title", "body"))
    }
}
