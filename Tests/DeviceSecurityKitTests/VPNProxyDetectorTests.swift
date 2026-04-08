import XCTest
@testable import DeviceSecurityKit

final class VPNProxyDetectorTests: XCTestCase {

    // MARK: - SecurityThreat

    func testVPNProxyThreatSeverity() {
        XCTAssertEqual(SecurityThreat.vpnProxy.severity, .medium)
    }

    func testVPNProxyDescription_nonEmpty() {
        XCTAssertFalse(SecurityThreat.vpnProxy.description.isEmpty)
    }

    // MARK: - SecurityStatus

    func testVPNProxyStatusDescription_nonEmpty() {
        XCTAssertFalse(SecurityStatus.vpnProxy.description.isEmpty)
        XCTAssertFalse(SecurityStatus.vpnProxy.isSecure)
    }

    // MARK: - SecurityResult

    func testIsVPNOrProxyActive_whenThreatPresent() {
        let result = SecurityResult(threats: [.vpnProxy])
        XCTAssertTrue(result.isVPNOrProxyActive)
        XCTAssertFalse(result.isSecure)
    }

    func testIsVPNOrProxyActive_whenThreatAbsent() {
        let result = SecurityResult(threats: [])
        XCTAssertFalse(result.isVPNOrProxyActive)
        XCTAssertTrue(result.isSecure)
    }

    // MARK: - DeviceSecurityConfiguration

    func testDefaultConfigHasVPNProxyEnabled() {
        XCTAssertTrue(DeviceSecurityConfiguration.default.vpnProxyDetectionEnabled)
    }

    func testWithVPNProxyDetection_disables() {
        let config = DeviceSecurityConfiguration.default.withVPNProxyDetection(false)
        XCTAssertFalse(config.vpnProxyDetectionEnabled)
    }

    func testWithVPNProxyDetection_enables() {
        let config = DeviceSecurityConfiguration.default
            .withVPNProxyDetection(false)
            .withVPNProxyDetection(true)
        XCTAssertTrue(config.vpnProxyDetectionEnabled)
    }

    // MARK: - Detector (smoke test)
    func testIsVPNOrProxyActive_returnsBoolean() {
        let _ = VPNProxyDetector.isVPNOrProxyActive()
    }
}
