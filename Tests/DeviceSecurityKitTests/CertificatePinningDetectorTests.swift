import XCTest
@testable import DeviceSecurityKit

final class CertificatePinningDetectorTests: XCTestCase {

    // MARK: - SecurityThreat

    func testPinningBypassedThreatSeverity() {
        XCTAssertEqual(SecurityThreat.pinningBypassed.severity, .critical)
    }

    func testPinningBypassedDescription_nonEmpty() {
        XCTAssertFalse(SecurityThreat.pinningBypassed.description.isEmpty)
    }

    // MARK: - SecurityStatus

    func testPinningBypassedStatusDescription_nonEmpty() {
        XCTAssertFalse(SecurityStatus.pinningBypassed.description.isEmpty)
        XCTAssertFalse(SecurityStatus.pinningBypassed.isSecure)
    }

    // MARK: - SecurityResult

    func testIsPinningBypassed_whenThreatPresent() {
        let result = SecurityResult(threats: [.pinningBypassed])
        XCTAssertTrue(result.isPinningBypassed)
        XCTAssertFalse(result.isSecure)
    }

    func testIsPinningBypassed_whenThreatAbsent() {
        let result = SecurityResult(threats: [])
        XCTAssertFalse(result.isPinningBypassed)
        XCTAssertTrue(result.isSecure)
    }

    // MARK: - DeviceSecurityConfiguration

    func testDefaultConfigHasPinningBypassEnabled() {
        XCTAssertTrue(DeviceSecurityConfiguration.default.pinningBypassDetectionEnabled)
    }

    func testWithPinningBypassDetection_disables() {
        let config = DeviceSecurityConfiguration.default.withPinningBypassDetection(false)
        XCTAssertFalse(config.pinningBypassDetectionEnabled)
    }

    func testWithPinningBypassDetection_enables() {
        let config = DeviceSecurityConfiguration.default
            .withPinningBypassDetection(false)
            .withPinningBypassDetection(true)
        XCTAssertTrue(config.pinningBypassDetectionEnabled)
    }

    // MARK: - Detector (smoke test — can't fully test in simulator)

    func testIsPinningBypassed_returnsBoolean() {
        // Just verify it doesn't crash and returns a value.
        // Actual bypass checks are hardware/runtime-specific.
        let _ = CertificatePinningDetector.isPinningBypassed()
    }
}
