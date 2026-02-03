import Foundation
import Darwin

public final class DebuggerDetector {
    
    // MARK: - Public
    public static func isDebuggerAttached() -> Bool {
        return checkDebuggerWithSysctl()
            || checkDebuggerWithPtrace()
    }
    
    // MARK: - Private
    private static func checkDebuggerWithSysctl() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        
        guard result == 0 else { return false }
        
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    private static func checkDebuggerWithPtrace() -> Bool {
        #if !DEBUG
        let PT_DENY_ATTACH: Int32 = 31
        let result = DeviceSecurityKit.ptrace(PT_DENY_ATTACH, 0, nil, 0)
        return result == -1
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
