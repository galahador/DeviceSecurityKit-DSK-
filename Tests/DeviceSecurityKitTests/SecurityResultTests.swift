import XCTest
@testable import DeviceSecurityKit

final class SecurityResultTests: XCTestCase {

    func testSecureWhenNoThreat() {
        let result = SecurityResult(threats: [.noThreat])
        XCTAssertTrue(result.isSecure)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertFalse(result.isDebuggerAttached)
        XCTAssertFalse(result.isEmulator)
        XCTAssertFalse(result.isReverseEngineered)
        XCTAssertFalse(result.isScreenRecorded)
    }

    func testStaticSecureConstant() {
        XCTAssertTrue(SecurityResult.secure.threats.isEmpty)
    }

    func testJailbreakThreat() {
        let result = SecurityResult(threats: [.jailbreak])
        XCTAssertFalse(result.isSecure)
        XCTAssertTrue(result.isJailbroken)
        XCTAssertFalse(result.isDebuggerAttached)
    }

    func testDebuggerThreat() {
        let result = SecurityResult(threats: [.debugger])
        XCTAssertFalse(result.isSecure)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertTrue(result.isDebuggerAttached)
    }

    func testMultipleThreats() {
        let result = SecurityResult(threats: [.jailbreak, .reverseEngineering])
        XCTAssertFalse(result.isSecure)
        XCTAssertTrue(result.isJailbroken)
        XCTAssertTrue(result.isReverseEngineered)
        XCTAssertEqual(result.threats.count, 2)
    }

    func testEquality() {
        let a = SecurityResult(threats: [.jailbreak])
        let b = SecurityResult(threats: [.jailbreak])
        let c = SecurityResult(threats: [.debugger])
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }
}
