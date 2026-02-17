import Foundation

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
    
    private static func checkSuspiciousURLSchemes() -> Bool {
        for scheme in jailbreakListOptions.urlSchemes {
            // TODO: - Check This in future 
//            if let url = URL(string: scheme) {
//                if UIApplication.shared.canOpenURL(url) {
//                    return true
//                }
//            }
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
}
