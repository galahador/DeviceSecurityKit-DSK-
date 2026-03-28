import XCTest
@testable import DeviceSecurityKit

final class SecurityThreatTests: XCTestCase {

    func testSeverityLevels() {
        XCTAssertEqual(SecurityThreat.jailbreak.severity, .critical)
        XCTAssertEqual(SecurityThreat.reverseEngineering.severity, .critical)
        XCTAssertEqual(SecurityThreat.debugger.severity, .high)
        XCTAssertEqual(SecurityThreat.emulator.severity, .medium)
    }

    func testSeverityComparison() {
        XCTAssertLessThan(ThreatSeverity.low, .medium)
        XCTAssertLessThan(ThreatSeverity.medium, .high)
        XCTAssertLessThan(ThreatSeverity.high, .critical)
        XCTAssertGreaterThan(ThreatSeverity.critical, .low)
    }

    func testDescriptions_nonEmpty() {
        for threat in SecurityThreat.allCases {
            XCTAssertFalse(threat.description.isEmpty, "Missing description for \(threat)")
        }
    }

    func testHashable() {
        let set: Set<SecurityThreat> = [.jailbreak, .jailbreak, .debugger]
        XCTAssertEqual(set.count, 2)
    }

    func testAllCasesCount() {
        XCTAssertEqual(SecurityThreat.allCases.count, 4)
    }
}
