import XCTest
@testable import DeviceSecurityKit

// MARK: - Mock provider

private struct AlwaysRecordingProvider: ScreenRecordingProvider {
    func isScreenBeingRecorded() -> Bool { true }
}

private struct NeverRecordingProvider: ScreenRecordingProvider {
    func isScreenBeingRecorded() -> Bool { false }
}

// MARK: - Tests

final class ScreenRecordingTests: XCTestCase {

    func testThreatDetected_whenProviderReturnsTrue() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.screenRecordingProvider = AlwaysRecordingProvider()

        let result = monitor.performCheck()
        XCTAssertTrue(result.isScreenRecorded)
    }

    func testNoThreat_whenProviderReturnsFalse() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        monitor.screenRecordingProvider = NeverRecordingProvider()

        let result = monitor.performCheck()
        XCTAssertFalse(result.isScreenRecorded)
    }

    func testNoThreat_whenProviderNotInjected() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(true))
        // No provider set — check must be skipped silently

        let result = monitor.performCheck()
        XCTAssertFalse(result.isScreenRecorded)
    }

    func testNoThreat_whenCheckDisabled() {
        let monitor = SecurityMonitor(configuration: .disabled.withScreenRecordingCheck(false))
        monitor.screenRecordingProvider = AlwaysRecordingProvider()

        let result = monitor.performCheck()
        XCTAssertFalse(result.isScreenRecorded)
    }

    func testSecurityResult_isScreenRecorded() {
        let result = SecurityResult(threats: [.screenRecording])
        XCTAssertTrue(result.isScreenRecorded)
        XCTAssertFalse(result.isJailbroken)
    }
}
