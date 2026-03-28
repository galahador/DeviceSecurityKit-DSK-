import Foundation
import Darwin

public final class JailbreakDetector {
    
    // MARK: - Private Properties
    private static let jailbreakListOptions = JailbreakListOptions()
    
    // MARK: - Public
    
    public static var urlSchemeChecker: ((URL) -> Bool)?
    /// Main jailbreak detection method
    public static func isJailbroken() -> Bool {
        return checkJailbreakFiles()
        || checkSandboxIntegrity()
        || checkForkCapability()
        || checkSuspiciousURLSchemes()
        || checkSymbolicLinks()
        || checkSuspiciousEnvironmentVars()
        || checkPrebootJailbreakPaths()
    }
    
    // MARK: - Private Detection Methods
    
    private static func checkJailbreakFiles() -> Bool {
        for path in jailbreakListOptions.suspiciousPaths {
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
    
    private static func checkSuspiciousEnvironmentVars() -> Bool {
        for envVar in jailbreakListOptions.suspiciousVars {
            if getenv(envVar) != nil {
                return true
            }
        }
        return false
    }
    
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
