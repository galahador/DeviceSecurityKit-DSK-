import Foundation
import Darwin

public final class JailbreakDetector {

    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()
    private static let detectionQueue = DispatchQueue(label: "JailbreakDetector.detection", attributes: .concurrent)

    // MARK: - Master Switch

    private static var _isDetectionEnabled: Bool = true

    /// Enables or disables all jailbreak detection. When false, isJailbroken() always returns false.
    public static var isDetectionEnabled: Bool {
        get { detectionQueue.sync { _isDetectionEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isDetectionEnabled = newValue } }
    }

    // MARK: - Per-Check Switches

    private static var _isFileCheckEnabled: Bool = true
    private static var _isSandboxCheckEnabled: Bool = true
    private static var _isForkCheckEnabled: Bool = true
    private static var _isURLSchemeCheckEnabled: Bool = true
    private static var _isSymbolicLinkCheckEnabled: Bool = true
    private static var _isEnvironmentVarCheckEnabled: Bool = true
    private static var _isPrebootCheckEnabled: Bool = true

    public static var isFileCheckEnabled: Bool {
        get { detectionQueue.sync { _isFileCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isFileCheckEnabled = newValue } }
    }

    public static var isSandboxCheckEnabled: Bool {
        get { detectionQueue.sync { _isSandboxCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isSandboxCheckEnabled = newValue } }
    }

    public static var isForkCheckEnabled: Bool {
        get { detectionQueue.sync { _isForkCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isForkCheckEnabled = newValue } }
    }

    public static var isURLSchemeCheckEnabled: Bool {
        get { detectionQueue.sync { _isURLSchemeCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isURLSchemeCheckEnabled = newValue } }
    }

    public static var isSymbolicLinkCheckEnabled: Bool {
        get { detectionQueue.sync { _isSymbolicLinkCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isSymbolicLinkCheckEnabled = newValue } }
    }

    public static var isEnvironmentVarCheckEnabled: Bool {
        get { detectionQueue.sync { _isEnvironmentVarCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isEnvironmentVarCheckEnabled = newValue } }
    }

    public static var isPrebootCheckEnabled: Bool {
        get { detectionQueue.sync { _isPrebootCheckEnabled } }
        set { detectionQueue.sync(flags: .barrier) { _isPrebootCheckEnabled = newValue } }
    }

    // MARK: - URL Scheme Checker
    /// The host app must also declare the jailbreak URL schemes in LSApplicationQueriesSchemes
    /// in its Info.plist, otherwise canOpenURL always returns false on iOS 9+.
    public static var urlSchemeChecker: ((URL) -> Bool)?

    // MARK: - Public

    /// Main jailbreak detection method
    public static func isJailbroken() -> Bool {
        guard isDetectionEnabled else { return false }

        return (_isFileCheckEnabled         && checkJailbreakFiles())
            || (_isSandboxCheckEnabled      && checkSandboxIntegrity())
            || (_isForkCheckEnabled         && checkForkCapability())
            || (_isURLSchemeCheckEnabled    && checkSuspiciousURLSchemes())
            || (_isSymbolicLinkCheckEnabled && checkSymbolicLinks())
            || (_isEnvironmentVarCheckEnabled && checkSuspiciousEnvironmentVars())
            || (_isPrebootCheckEnabled      && checkPrebootJailbreakPaths())
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

    /// Checks for jailbreak-related URL schemes using the injected urlSchemeChecker.
    /// Silently skipped if urlSchemeChecker has not been set.
    private static func checkSuspiciousURLSchemes() -> Bool {
        guard let checker = urlSchemeChecker else { return false }

        for scheme in jailbreakListOptions.urlSchemes {
            if let url = URL(string: scheme), checker(url) {
                return true
            }
        }

        return false
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

    /// Sandboxed iOS apps cannot fork(). A successful fork means the sandbox has been bypassed.
    /// fork() is loaded dynamically to bypass the Swift compile-time unavailability restriction —
    /// the kernel still exposes it, so this tests whether the sandbox actually blocks the syscall.
    private static func checkForkCapability() -> Bool {
        typealias ForkType = @convention(c) () -> pid_t

        guard let handle = dlopen(nil, RTLD_NOW),
              let sym = dlsym(handle, "fork") else { return false }
        dlclose(handle)

        let forkFn = unsafeBitCast(sym, to: ForkType.self)
        let pid = forkFn()
        if pid == 0 {
            // Child process — fork succeeded, which must not happen in a sandbox
            exit(0)
        }
        return pid > 0
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
