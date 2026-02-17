//
//  File.swift
//  DeviceSecurityKit
//
//  Created by tBug on 17. 2. 2026..
//

import Foundation

struct DebuggerDetectorList {
    let suspiciousNames = [
        "lldb", "gdb", "debugserver", "xpcproxy",
        "instruments", "dtrace", "dtruss", "fs_usage",
        "sample", "spindump", "crashreporterd"
    ]
    
    let suspiciousEnvVars = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_INTERPOSE",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_APIS",
        "LLDB_DEBUGSERVER_PATH",
        "INSTRUMENTS_DT_CORE_SIMULATOR_PATH"
    ]
}
