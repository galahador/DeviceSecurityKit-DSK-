import Foundation
import Darwin

public final class EmulatorDetector {
    
    // MARK: - Public Types
    
    public struct DetectionResult {
        public let isEmulator: Bool
        public let detectionMethods: [String]
        public let confidence: Float
        public let timestamp: Date
        
        public init(isEmulator: Bool, detectionMethods: [String], confidence: Float) {
            self.isEmulator = isEmulator
            self.detectionMethods = detectionMethods
            self.confidence = confidence
            self.timestamp = Date()
        }
    }
    
    // MARK: - Private Properties
    
    private static let logger = SecurityLogger.detection(subsystem: "DeviceSecurityKit")
    private static let emulatorDetectorListOptions = EmulatorDetectorListOptions()
    
    private static var cachedDeviceModel: String?
    private static let cacheQueue = DispatchQueue(label: "com.devicesecuritykit.emulator.cache", attributes: .concurrent)
    
    // MARK: - Public Methods
    
    public static func isEmulator() -> Bool {
        let result = detectEmulator()
        return result.isEmulator
    }
    
    public static func detectEmulator() -> DetectionResult {
        logger.info("Starting comprehensive emulator detection")
        
        var detectionMethods: [String] = []
        var confidenceScore: Float = 0.0
        let totalChecks: Float = 6.0
        
        if checkSimulatorEnvironment() {
            detectionMethods.append("targetEnvironment(simulator)")
            confidenceScore += 2.0
            logger.warning("Emulator detected via compilation target")
        }
        
        if checkSimulatorPaths() {
            detectionMethods.append("simulatorPaths")
            confidenceScore += 1.5
            logger.warning("Emulator detected via filesystem paths")
        }
        
        if checkDeviceModel() {
            detectionMethods.append("deviceModel")
            confidenceScore += 1.5
            logger.warning("Emulator detected via device model")
        }
        
        if checkSystemProperties() {
            detectionMethods.append("systemProperties")
            confidenceScore += 2.0
            logger.warning("Emulator detected via system properties")
        }
        
        if checkRuntimeEnvironment() {
            detectionMethods.append("runtimeEnvironment")
            confidenceScore += 0.8
            logger.warning("Emulator detected via runtime environment")
        }
        
        if checkProcessEnvironment() {
            detectionMethods.append("processEnvironment")
            confidenceScore += 1.2
            logger.warning("Emulator detected via process environment")
        }
        
        let confidence = min(confidenceScore / totalChecks, 1.0)
        let isEmulator = confidence > 0.25
        
        let result = DetectionResult(
            isEmulator: isEmulator,
            detectionMethods: detectionMethods,
            confidence: confidence
        )
        
        if isEmulator {
            logger.error("Emulator detected with confidence: \(String(format: "%.2f", confidence * 100))%. Methods: \(detectionMethods.joined(separator: ", "))")
        } else {
            logger.info("No emulator detected. Running on physical iOS device.")
        }
        
        return result
    }
    
    // MARK: - Private Detection Methods
    
    private static func checkSimulatorEnvironment() -> Bool {
#if targetEnvironment(simulator)
        return true
#else
        return false
#endif
    }
    
    private static func checkSimulatorPaths() -> Bool {
        let criticalPaths = [
            "/System/Library/CoreServices/CoreSimulatorBridge.app",
            "/System/Library/PrivateFrameworks/CoreSimulator.framework",
            "/Library/Developer/CoreSimulator"
        ]
        
        let additionalPaths = emulatorDetectorListOptions.simulatorPaths + [
            "/usr/bin/simctl",
            "/private/var/containers/Bundle/Application"
        ]
        
        for path in criticalPaths {
            if FileManager.default.fileExists(atPath: path) {
                logger.debug("Found critical emulator-specific path: \(path)")
                return true
            }
        }
        
        var additionalMatches = 0
        for path in additionalPaths {
            if FileManager.default.fileExists(atPath: path) {
                additionalMatches += 1
                logger.debug("Found additional simulator path: \(path)")
            }
        }
        
        return additionalMatches >= 2
    }
    
    private static func checkDeviceModel() -> Bool {
        let modelIdentifier = getDeviceModelIdentifier()
        
        let simulatorOnlyIdentifiers = [
            "i386",
            "x86_64"
        ]
        
        for identifier in simulatorOnlyIdentifiers {
            if modelIdentifier.lowercased() == identifier.lowercased() {
                logger.debug("Detected simulator-only architecture: \(modelIdentifier)")
                return true
            }
        }
        
        if modelIdentifier.lowercased().contains("simulator") {
            logger.debug("Found 'Simulator' in model identifier: \(modelIdentifier)")
            return true
        }
        
        if modelIdentifier == "arm64" {
            return checkIfSimulatorOnAppleSilicon()
        }
        
        return false
    }
    
    private static func checkIfSimulatorOnAppleSilicon() -> Bool {
        let processName = ProcessInfo.processInfo.processName
        let environment = ProcessInfo.processInfo.environment
        
        if environment["SIMULATOR_DEVICE_NAME"] != nil ||
            environment["SIMULATOR_VERSION_INFO"] != nil {
            return true
        }
        
        if processName.contains("Simulator") || processName.contains("simulator") {
            return true
        }
        
        return false
    }
    
    private static func checkSystemProperties() -> Bool {
        
        for envVar in EmulatorDetector.emulatorDetectorListOptions.suspiciousEnvVars {
            if let value = getenv(envVar) {
                logger.debug("Found simulator environment variable: \(envVar) = \(String(cString: value))")
                return true
            }
        }
        
        return false
    }
    
    private static func checkRuntimeEnvironment() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        
        let result = mib.withUnsafeMutableBufferPointer { mibPtr in
            sysctl(mibPtr.baseAddress, 4, &info, &size, nil, 0)
        }
        
        if result == 0 {
            let isDebuggerAttached = (info.kp_proc.p_flag & P_TRACED) != 0
            
            if isDebuggerAttached {
                let environment = ProcessInfo.processInfo.environment
                let hasSimulatorEnv = environment["SIMULATOR_DEVICE_NAME"] != nil ||
                environment["SIMULATOR_VERSION_INFO"] != nil
                
                if hasSimulatorEnv {
                    logger.debug("Debugger attachment detected in simulator environment")
                    return true
                }
                logger.debug("Debugger detected but appears to be real device debugging")
            }
        }
        
        return false
    }
    
    private static func checkProcessEnvironment() -> Bool {
        let processName = ProcessInfo.processInfo.processName
        let arguments = ProcessInfo.processInfo.arguments
        
        if processName.lowercased().contains("simulator") {
            logger.debug("Process name contains 'simulator': \(processName)")
            return true
        }
        
        for argument in arguments {
            if argument.contains("Simulator") || argument.contains("/CoreSimulator/") {
                logger.debug("Found simulator-specific argument: \(argument)")
                return true
            }
        }
        
        let bundlePath = Bundle.main.bundlePath
        if bundlePath.contains("CoreSimulator") || bundlePath.contains("Simulator") {
            logger.debug("Bundle path indicates simulator: \(bundlePath)")
            return true
        }
        
        return false
    }
    
    // MARK: - Helper Methods
    
    private static func getDeviceModelIdentifier() -> String {
        return cacheQueue.sync {
            if let cached = cachedDeviceModel {
                return cached
            }
            
            var systemInfo = utsname()
            uname(&systemInfo)
            let identifier = withUnsafePointer(to: &systemInfo.machine) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                    String(validatingUTF8: $0) ?? "Unknown"
                }
            }
            
            cacheQueue.async(flags: .barrier) {
                cachedDeviceModel = identifier
            }
            
            return identifier
        }
    }
}
