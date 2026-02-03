import Foundation

public final class EmulatorDetector {
    
    // MARK: - Private Properties
    private static var emulatorDetectorListOptions = EmulatorDetectorListOptions()
    
    // MARK: - Public
    public static func isEmulator() -> Bool {
        return checkSimulatorEnvironment()
            || checkSimulatorPaths()
    }
    
    // MARK: - Private
    private static func checkSimulatorEnvironment() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    private static func checkSimulatorPaths() -> Bool {
        for path in emulatorDetectorListOptions.simulatorPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
}
