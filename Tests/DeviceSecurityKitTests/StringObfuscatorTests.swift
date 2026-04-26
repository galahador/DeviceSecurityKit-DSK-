//
//  StringObfuscatorTests.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import XCTest
@testable import DeviceSecurityKit

final class StringObfuscatorTests: XCTestCase {

    private let obfuscator = StringObfuscator.shared

    func testRoundTrip_ascii() {
        let samples = [
            "FridaGadget",
            "DYLD_INSERT_LIBRARIES",
            "/var/containers/Bundle/Application/",
            "_SafeMode",
            "libhooker"
        ]
        for original in samples {
            let encoded = obfuscator.conceal(original)
            let decoded = obfuscator.reveal(encoded)
            XCTAssertEqual(decoded, original, "Round-trip failed for: \(original)")
        }
    }

    func testRoundTrip_emptyString() {
        let encoded = obfuscator.conceal("")
        XCTAssertTrue(encoded.isEmpty)
        XCTAssertEqual(obfuscator.reveal(encoded), "")
    }

    func testEncodedBytesAreNotPlaintext() {
        let original = "FridaGadget"
        let encoded = obfuscator.conceal(original)
        let originalBytes = Array(original.utf8)
        XCTAssertNotEqual(encoded, originalBytes)
    }

    func testRevealKnownBytes_fridaGadget() {
        let bytes: [UInt8] = [0xEC, 0xD8, 0xC3, 0xCE, 0xCB, 0xED, 0xCB, 0xCE, 0xCD, 0xCF, 0xDE]
        XCTAssertEqual(obfuscator.reveal(bytes), "FridaGadget")
    }

    func testRevealKnownBytes_dyldInsertLibraries() {
        let bytes: [UInt8] = [0xEE, 0xF3, 0xE6, 0xEE, 0xF5, 0xE3, 0xE4, 0xF9, 0xEF, 0xF8, 0xFE,
                              0xF5, 0xE6, 0xE3, 0xE8, 0xF8, 0xEB, 0xF8, 0xE3, 0xEF, 0xF9]
        XCTAssertEqual(obfuscator.reveal(bytes), "DYLD_INSERT_LIBRARIES")
    }

    func testRevealKnownBytes_validBundlePath() {
        let bytes: [UInt8] = [0x85, 0xDC, 0xCB, 0xD8, 0x85, 0xC9, 0xC5, 0xC4, 0xDE, 0xCB, 0xC3,
                              0xC4, 0xCF, 0xD8, 0xD9, 0x85, 0xE8, 0xDF, 0xC4, 0xCE, 0xC6, 0xCF,
                              0x85, 0xEB, 0xDA, 0xDA, 0xC6, 0xC3, 0xC9, 0xCB, 0xDE, 0xC3, 0xC5,
                              0xC4, 0x85]
        XCTAssertEqual(obfuscator.reveal(bytes), "/var/containers/Bundle/Application/")
    }
}
