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

    /// Checks that the app is running from a legitimate iOS install location.
    private static func checkCodeIntegrity() -> Bool {
        guard let executablePath = Bundle.main.executablePath else { return false }

        // Executable must still exist on disk
        guard FileManager.default.fileExists(atPath: executablePath) else { return true }

        #if !targetEnvironment(simulator)
        let bundlePath = Bundle.main.bundlePath
        let validPrefixes = [
            "/var/containers/Bundle/Application/",
            "/private/var/containers/Bundle/Application/"
        ]
        if !validPrefixes.contains(where: { bundlePath.hasPrefix($0) }) {
            return true
        }
        #endif

        return false
    }
}
