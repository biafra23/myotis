import XCTest

/// Drives the shared Compose UI end-to-end on the simulator: open the Query
/// tab, look up an address, and wait for the beacon-verified result. Compose
/// maps its semantics into the iOS accessibility tree, so tabs/buttons/fields
/// resolve by their visible text.
final class QueryFlowTests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testQueryVitaliksAccount() throws {
        // activate(), not launch(): attach to the app that is already running
        // (and already synced) instead of restarting it — a fresh boot would
        // have to re-bootstrap the beacon sync and re-hunt snap peers first.
        let app = XCUIApplication()
        app.activate()

        // The engine boots with the app; give the Status tab a moment to render.
        XCTAssertTrue(app.staticTexts["Myotis"].waitForExistence(timeout: 30))

        // Query tab. Compose tabs surface as plain text elements.
        let queryTab = app.staticTexts["Query"]
        XCTAssertTrue(queryTab.waitForExistence(timeout: 10))
        queryTab.tap()

        // Compose's TextField isn't exposed as an XCUI textField (Text/tabs DO
        // surface as staticTexts) — wait for the field's label to render, tap
        // the field by normalized position, then type into the focused field.
        // Positions measured against the rendered Query layout: the field sits
        // directly under the tab row, the Look up button under the field.
        XCTAssertTrue(app.staticTexts["Address (0x…) or ENS name"].waitForExistence(timeout: 10))
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.29)).tap()
        // Best-effort keyboard wait: with a hardware keyboard attached the
        // software keyboard may legitimately never appear, and typeText still
        // reaches the focused field — so don't assert on it.
        _ = app.keyboards.firstMatch.waitForExistence(timeout: 3)
        app.typeText("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

        let lookUp = app.staticTexts["Look up"]
        XCTAssertTrue(lookUp.waitForExistence(timeout: 5))
        lookUp.tap()

        // A verified account read walks snap + the verification ladder — allow
        // the full 90 s bound, then attach the rendered result to the test
        // output as the durable evidence (no trailing sleep).
        let result = app.staticTexts["Balance (ETH)"]
        XCTAssertTrue(result.waitForExistence(timeout: 120), "no account result rendered")
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "verified-account-result"
        shot.lifetime = .keepAlways
        add(shot)
    }
}
