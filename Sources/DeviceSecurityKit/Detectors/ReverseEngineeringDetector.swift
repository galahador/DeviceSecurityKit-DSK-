import Foundation
import Darwin
import MachO

public final class ReverseEngineeringDetector {
    
    // MARK: - Private Properties
    private static var reverseEngineeringListsOptions = ReverseEngineeringListsOptions()
    
    // MARK: - Public
    public static func isReverseEngineered() -> Bool {
        return checkSuspiciousLibraries()
            || checkEnvironmentVariables()
            || checkCodeIntegrity()
    }
    
    // MARK: - Private
    private static func checkSuspiciousLibraries() -> Bool {
        for libraryName in reverseEngineeringListsOptions.suspiciousLibraries {
            if checkIfLibraryLoaded(libraryName) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkIfLibraryLoaded(_ libraryName: String) -> Bool {
        let maxImages = _dyld_image_count()
        
        for i in 0..<maxImages {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            
            if name.lowercased().contains(libraryName.lowercased()) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkEnvironmentVariables() -> Bool {
        for varName in reverseEngineeringListsOptions.suspiciousVars {
            if let value = getenv(varName), String(cString: value).count > 0 {
                return true
            }
        }
        return false
    }
    
    private static func checkCodeIntegrity() -> Bool {
        guard let executablePath = Bundle.main.executablePath else { return false }
        
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: executablePath)
            
            if let modificationDate = attributes[.modificationDate] as? Date {
                let timeSinceModification = Date().timeIntervalSince(modificationDate)
                
                if timeSinceModification < 3600 {
                    return true
                }
            }
        } catch {
            // Silent fail
        }
        
        return false
    }
}
