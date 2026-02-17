import Foundation
import Foundation
import Darwin

public final class DebuggerDetector {
    
    // MARK: - Private Properties
    private static let logger = SecurityLogger.security(subsystem: "DebuggerDetector")
    private static let debuggerDetectorList = DebuggerDetectorList()
    
    /// Disable all debugger detection
    public static var isDetectionEnabled: Bool = true
    
    // MARK: - Public Methods
    
    /// Main debugger detection
    public static func isDebuggerAttached() -> Bool {
        // Allow disabling detection for testing purposes
        guard isDetectionEnabled else {
            logger.debug("Debugger detection is disabled")
            return false
        }
        
        let detectionResults = [
            ("sysctl", checkDebuggerWithSysctl()),
            ("ptrace", checkDebuggerWithPtrace()),
            ("parentProcess", checkDebuggerWithGetppid()),
            ("environment", checkDebuggerEnvironment()),
            ("timing", checkTimingAnalysis()),
            ("breakpoint", checkBreakpointDetection())
        ]
        
#if DEBUG
        for (method, detected) in detectionResults {
            if detected {
                logger.debug("Debugger detection method '\(method)' triggered")
            }
        }
        return false
#else
        // In release builds, return true if any method detects a debugger
        let isAttached = detectionResults.contains { $0.1 }
        if isAttached {
            let triggeredMethods = detectionResults.compactMap { $0.1 ? $0.0 : nil }.joined(separator: ", ")
            logger.warning("Debugger attachment detected via methods: \(triggeredMethods)")
        }
        return isAttached
#endif
    }
    
    public static func getDetectionResults() -> [String: Bool] {
        guard isDetectionEnabled else {
            return [:]
        }
        
        return [
            "sysctl": checkDebuggerWithSysctl(),
            "ptrace": checkDebuggerWithPtrace(),
            "parentProcess": checkDebuggerWithGetppid(),
            "environment": checkDebuggerEnvironment(),
            "timing": checkTimingAnalysis(),
            "breakpoint": checkBreakpointDetection()
        ]
    }
    
    // MARK: - Detection Methods
    
    private static func checkDebuggerWithSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error("sysctl failed with result: \(result)")
            return false
        }
        
        // Check for P_TRACED flag
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    /// Check for PT_DENY_ATTACH
    private static func checkDebuggerWithPtrace() -> Bool {
#if !DEBUG
        let PT_DENY_ATTACH: Int32 = 31
        
        // Save original errno
        let originalErrno = errno
        errno = 0
        
        // Try to call ptrace with PT_DENY_ATTACH
        let result = ptrace(PT_DENY_ATTACH, 0, nil, 0)
        
        // Check if ptrace failed due to debugger attachment
        let ptraceErrno = errno
        errno = originalErrno // Restore original errno
        
        let detected = result == -1 && (ptraceErrno == EPERM || ptraceErrno == EBUSY)
        if detected {
            logger.info("ptrace detection triggered with errno: \(ptraceErrno)")
        }
        
        return detected
#else
        return false
#endif
    }
    
    private static func checkDebuggerWithGetppid() -> Bool {
        let parentPid = getppid()
        
        // Get parent process information
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parentPid]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else { return false }
        
        // Extract process name
        let processName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            return String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
        }
        
        let detected = DebuggerDetector.debuggerDetectorList.suspiciousNames.contains(processName.lowercased())
        if detected {
            logger.info("Suspicious parent process detected: \(processName)")
        }
        
        return detected
    }
    
    /// Check for debugger-related environment variables
    private static func checkDebuggerEnvironment() -> Bool {
        for envVar in DebuggerDetector.debuggerDetectorList.suspiciousEnvVars {
            if let value = getenv(envVar) {
                let envValue = String(cString: value)
                logger.info("Suspicious environment variable detected: \(envVar)=\(envValue)")
                return true
            }
        }
        
        return false
    }
    
    /// Timing-based debugger detection
    private static func checkTimingAnalysis() -> Bool {
#if !DEBUG
        let startTime = mach_absolute_time()
        
        var dummy = 0
        for i in 0..<1000 {
            dummy += i
        }
        
        let endTime = mach_absolute_time()
        
        var timebaseInfo = mach_timebase_info()
        mach_timebase_info(&timebaseInfo)
        
        let elapsed = (endTime - startTime) * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
        
        let detected = elapsed > 10_000_000 // 10ms in nanoseconds
        if detected {
            logger.info("Timing analysis detected slow execution: \(elapsed)ns")
        }
        return detected
#else
        return false
#endif
    }
    
    /// Software breakpoint detection
    private static func checkBreakpointDetection() -> Bool {
#if !DEBUG
        // by examining memory for breakpoint instructions (0xCC on x86, various on ARM)
        
        let functionPtr = unsafeBitCast(checkBreakpointDetection, to: UnsafeRawPointer.self)
        
        let bytes = functionPtr.assumingMemoryBound(to: UInt8.self)
        
        for i in 0..<16 {
            let byte = bytes.advanced(by: i).pointee
            if byte == 0xCC || byte == 0xD4 {
                return true
            }
        }
        
        return false
#else
        return false
#endif
    }
}

// MARK: - C Interop
func ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: Int32) -> Int32 {
    typealias PtraceType = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32
    
    guard let handle = dlopen(nil, RTLD_NOW),
          let sym = dlsym(handle, "ptrace") else {
        return 0
    }
    
    let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
    return ptraceFunc(request, pid, addr, data)
}
