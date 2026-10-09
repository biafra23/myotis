import XCTest

/// CLI helper (not a regression test): open the Logs tab, filter on "rpc",
/// and hold the screen briefly so an external `simctl io screenshot` can
/// capture the filtered access-log lines. The Logs tab is Expert-mode only
/// (Settings → Expert mode), so turn it on first — in the app, or from the
/// shell before running this, which the app reads on its next start:
/// `xcrun simctl spawn booted defaults write <bundle id> expertMode -bool YES`.
final class LogsFilterShot: XCTestCase {

    func testFilterLogsForRpc() throws {
        let app = XCUIApplication()
        app.activate()
        XCTAssertTrue(app.staticTexts["Myotis"].waitForExistence(timeout: 20))
        XCTAssertTrue(
            app.staticTexts["Logs"].waitForExistence(timeout: 5),
            "no Logs tab — turn on Settings → Expert mode first (see the class comment)"
        )
        app.staticTexts["Logs"].tap()
        XCTAssertTrue(app.staticTexts["Filter — tag or message"].waitForExistence(timeout: 10))
        // The filter field sits directly under the tab row (Compose TextFields
        // aren't XCUI textFields — tap by position, type into the focused field).
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.29)).tap()
        _ = app.keyboards.firstMatch.waitForExistence(timeout: 3)
        app.typeText("rpc")
        sleep(12)
    }
}
