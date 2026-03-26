import Foundation
import UIKit

public final class JailbreakDetector {

    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()

    // MARK: - Public

    /// Main jailbreak detection method
    public static func isJailbroken() -> Bool {
        return checkJailbreakFiles()
            || checkSandboxIntegrity()
            || checkSuspiciousURLSchemes()
            || checkSymbolicLinks()
            || checkSuspiciousEnvironmentVars()
            || checkPrebootJailbreakPaths()
    }

    // MARK: - Private Detection Methods

    private static func checkJailbreakFiles() -> Bool {
        for path in jailbreakListOptions.jailbreakPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }

            if FileManager.default.isReadableFile(atPath: path) {
                return true
            }
        }

        return false
    }

    private static func checkSandboxIntegrity() -> Bool {
        for testPath in jailbreakListOptions.testPaths {
            do {
                try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
                try? FileManager.default.removeItem(atPath: testPath)
                return true
            } catch {
                continue
            }
        }

        return false
    }

    /// Checks for jailbreak-related URL schemes.
    /// NOTE: The host app must declare the schemes in LSApplicationQueriesSchemes
    /// in its Info.plist for canOpenURL to return true on iOS 9+.
    private static func checkSuspiciousURLSchemes() -> Bool {
        var detected = false
        let check = {
            for scheme in jailbreakListOptions.urlSchemes {
                if let url = URL(string: scheme),
                   UIApplication.shared.canOpenURL(url) {
                    detected = true
                    break
                }
            }
        }
        if Thread.isMainThread {
            check()
        } else {
            DispatchQueue.main.sync { check() }
        }
        return detected
    }

    private static func checkSymbolicLinks() -> Bool {
        for path in jailbreakListOptions.suspiciousPaths {
            do {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                if let fileType = attributes[.type] as? FileAttributeType,
                   fileType == .typeSymbolicLink {
                    return true
                }
            } catch {
                continue
            }
        }

        return false
    }

    /// Checks environment variables associated with jailbreak substrate/hooking frameworks.
    private static func checkSuspiciousEnvironmentVars() -> Bool {
        for envVar in jailbreakListOptions.suspiciousVars {
            if getenv(envVar) != nil {
                return true
            }
        }
        return false
    }

    /// Scans /private/preboot/<uuid>/jb paths used by rootless jailbreaks (dopamine, palera1n).
    /// FileManager does not expand glob patterns, so each UUID directory is enumerated manually.
    private static func checkPrebootJailbreakPaths() -> Bool {
        let prebootPath = "/private/preboot"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: prebootPath) else {
            return false
        }
        for entry in entries {
            let jbPath = "\(prebootPath)/\(entry)/jb"
            if FileManager.default.fileExists(atPath: jbPath)
                || FileManager.default.isReadableFile(atPath: jbPath) {
                return true
            }
        }
        return false
    }
}
