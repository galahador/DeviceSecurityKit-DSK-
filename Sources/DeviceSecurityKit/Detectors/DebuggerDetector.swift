import Foundation
import Darwin
import Darwin.C

public final class DebuggerDetector {
    
    private static let logger = SecurityLogger.security(subsystem: "DebuggerDetector")
    private static let debuggerDetectorList = DebuggerDetectorList()
    
    private static let detectionQueue = DispatchQueue(label: "DebuggerDetector.detection", attributes: .concurrent)
    private static var _isDetectionEnabled: Bool = true

    private static let denyAttachQueue = DispatchQueue(label: "DebuggerDetector.denyAttach", qos: .background)
    private static var denyAttachTimer: DispatchSourceTimer?
    
    /// debugger detection ( ON / OFF )
    public static var isDetectionEnabled: Bool {
        get {
            return detectionQueue.sync { _isDetectionEnabled }
        }
        set {
            detectionQueue.sync(flags: .barrier) { _isDetectionEnabled = newValue }
        }
    }
    
    // MARK: - Continuous PT_DENY_ATTACH Hardening

    /// Starts re-asserting PT_DENY_ATTACH on a background thread every `interval` seconds.
    public static func startContinuousDenyAttach(interval: TimeInterval = 1.0) {
#if !DEBUG
        guard denyAttachTimer == nil else { return }

        let timer = DispatchSource.makeTimerSource(queue: denyAttachQueue)
        timer.schedule(deadline: .now(), repeating: interval)
        timer.setEventHandler {
            let PT_DENY_ATTACH: Int32 = 31
            _ = ptrace(PT_DENY_ATTACH, 0, nil, 0)
        }
        timer.resume()
        denyAttachTimer = timer
        logger.debug("Continuous PT_DENY_ATTACH hardening started (interval: \(interval)s)")
#endif
    }

    /// Stops the continuous PT_DENY_ATTACH background timer.
    public static func stopContinuousDenyAttach() {
#if !DEBUG
        denyAttachTimer?.cancel()
        denyAttachTimer = nil
        logger.debug("Continuous PT_DENY_ATTACH hardening stopped")
#endif
    }

    /// Detects debugger attachment using multiple methods
    public static func isDebuggerAttached() -> Bool {
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
        let isAttached = detectionResults.contains { $0.1 }
        if isAttached {
            let triggeredMethods = detectionResults.compactMap { $0.1 ? $0.0 : nil }.joined(separator: ", ")
            logger.warning("Debugger attachment detected via methods: \(triggeredMethods)")
        }
        return isAttached
#endif
    }
    
    /// Returns detailed detection results for each method
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
    
    /// Checks P_TRACED flag via sysctl
    private static func checkDebuggerWithSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else {
            logger.error("sysctl failed with result: \(result), errno: \(errno)")
            return false
        }
        
        guard size >= MemoryLayout<kinfo_proc>.stride else {
            logger.error("sysctl returned insufficient data: \(size) bytes")
            return false
        }
        
        let isTraced = (info.kp_proc.p_flag & P_TRACED) != 0
        if isTraced {
            logger.info("P_TRACED flag detected via sysctl")
        }
        
        return isTraced
    }
    
    /// Detects debugger using PT_DENY_ATTACH
    private static func checkDebuggerWithPtrace() -> Bool {
#if !DEBUG
        let PT_DENY_ATTACH: Int32 = 31
        
        let originalErrno = errno
        errno = 0
        
        let result = ptrace(PT_DENY_ATTACH, 0, nil, 0)
        
        let ptraceErrno = errno
        errno = originalErrno
        
        // EPERM means sandbox restriction — not a debugger indicator, ignore it.
        // EBUSY means the process is already being traced by a debugger.
        let detected = result == -1 && ptraceErrno == EBUSY
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
        
        guard parentPid > 0 else {
            logger.error("Invalid parent PID: \(parentPid)")
            return false
        }
        
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parentPid]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else { 
            logger.error("Failed to get parent process info, sysctl returned: \(result)")
            return false 
        }
        
        let processName = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
            let buffer = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            return String(cString: buffer)
        }
        
        let detected = debuggerDetectorList.suspiciousNames.contains(processName.lowercased())
        if detected {
            logger.info("Suspicious parent process detected: \(processName)")
        }
        
        return detected
    }
    
    /// Scans environment variables for debugging tools
    private static func checkDebuggerEnvironment() -> Bool {
        for envVar in debuggerDetectorList.suspiciousEnvVars {
            if let value = getenv(envVar) {
                let envValue = String(cString: value)
                logger.info("Suspicious environment variable detected: \(envVar)=\(envValue)")
                return true
            }
        }
        
        return false
    }
    
    /// Detects debugger through execution timing analysis
    private static func checkTimingAnalysis() -> Bool {
#if !DEBUG
        let iterations = 1000
        var measurements: [UInt64] = []
        measurements.reserveCapacity(5)
        
        for _ in 0..<5 {
            let startTime = mach_absolute_time()
            
            var dummy = 0
            for i in 0..<iterations {
                dummy = dummy &+ i
            }
            
            let endTime = mach_absolute_time()
            measurements.append(endTime - startTime)
            
            withUnsafePointer(to: &dummy) { _ in }
        }
        
        var timebaseInfo = mach_timebase_info()
        mach_timebase_info(&timebaseInfo)
        
        let avgTime = measurements.reduce(0 as UInt64) { $0 &+ $1 } / UInt64(measurements.count)
        let elapsed = avgTime * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
        
        let detected = elapsed > 50_000_000
        if detected {
            logger.info("Timing analysis detected slow execution: \(elapsed)ns average")
        }
        return detected
#else
        return false
#endif
    }
    
    /// Breakpoint instructions
    private static func checkBreakpointDetection() -> Bool {
#if !DEBUG
        let functionPtr = unsafeBitCast(checkBreakpointDetection, to: UnsafeRawPointer.self)
        let bytes = functionPtr.assumingMemoryBound(to: UInt8.self)
        
        for i in 0..<16 {
            let byte = bytes.advanced(by: i).pointee
            
            #if arch(arm64)
            if byte == 0xD4 {
                if i + 3 < 16 {
                    let word = UInt32(bytes.advanced(by: i).pointee) |
                              (UInt32(bytes.advanced(by: i + 1).pointee) << 8) |
                              (UInt32(bytes.advanced(by: i + 2).pointee) << 16) |
                              (UInt32(bytes.advanced(by: i + 3).pointee) << 24)
                    if (word & 0xFFE0001F) == 0xD4200000 {
                        logger.info("ARM64 breakpoint instruction detected")
                        return true
                    }
                }
            }
            #else
            if byte == 0xCC {
                logger.info("x86/x64 breakpoint instruction detected")
                return true
            }
            #endif
        }
        
        return false
#else
        return false
#endif
    }
}

/// Dynamic ptrace function loading
private func ptrace(_ request: Int32, _ pid: pid_t, _ addr: UnsafeMutableRawPointer?, _ data: Int32) -> Int32 {
    typealias PtraceType = @convention(c) (Int32, pid_t, UnsafeMutableRawPointer?, Int32) -> Int32
    
    guard let handle = dlopen(nil, RTLD_NOW) else {
        return -1
    }
    defer { dlclose(handle) }
    
    guard let sym = dlsym(handle, "ptrace") else {
        return -1
    }
    
    let ptraceFunc = unsafeBitCast(sym, to: PtraceType.self)
    return ptraceFunc(request, pid, addr, data)
}
