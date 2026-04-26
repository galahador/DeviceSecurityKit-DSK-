//
//  HookDetectorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class HookDetectorTests: XCTestCase {

    func testNoHooksDetected_onCleanDevice() {
        XCTAssertFalse(HookDetector.isFunctionHooked())
    }

    func testSecurityResult_isFunctionHooked() {
        let result = SecurityResult(threats: [.hooked])
        XCTAssertTrue(result.isFunctionHooked)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertFalse(result.isSecure)
    }

    func testThreatSeverity_hooked_isCritical() {
        XCTAssertEqual(SecurityThreat.hooked.severity, .critical)
    }

    func testMonitor_hookCheck_disabled() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withHookDetection(false)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isFunctionHooked)
    }

    func testMonitor_hookCheck_enabled_cleanDevice() {
        let monitor = SecurityMonitor(
            configuration: .disabled.withHookDetection(true)
        )
        let result = monitor.performCheck()
        XCTAssertFalse(result.isFunctionHooked)
    }
}
