import XCTest

/// Not a test of anything — a CLI screenshot utility for the PHYSICAL device,
/// where `simctl io screenshot` has no counterpart. Attaches to the running
/// app (activate, not launch — don't disturb its state) and stores one
/// screenshot in the result bundle; extract it with `xcrun xcresulttool`.
final class ScreenshotTest: XCTestCase {

    func testCaptureScreenshot() throws {
        let app = XCUIApplication()
        app.activate()
        XCTAssertTrue(app.staticTexts["Myotis"].waitForExistence(timeout: 20))
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "device-screenshot"
        shot.lifetime = .keepAlways
        add(shot)
        // Belt for CLI extraction: also write the PNG into the runner's tmp
        // dir, for `devicectl device copy from --domain-type appDataContainer`
        // (result-bundle attachment export has proven flaky from the command
        // line; note the runner may get an ephemeral container per run, so
        // this too is best-effort).
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
        try app.screenshot().pngRepresentation.write(to: tmp.appendingPathComponent("shot.png"))
    }
}
