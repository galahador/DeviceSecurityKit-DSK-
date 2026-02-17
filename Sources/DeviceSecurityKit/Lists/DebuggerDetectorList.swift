//
//  File.swift
//  DeviceSecurityKit
//
//  Created by tBug on 17. 2. 2026..
//

import Foundation

struct DebuggerDetectorList {
    let suspiciousNames = [
        "lldb",
        "gdb",
        "debugserver",
        "xpcproxy",
        "frida",
        "objection",
        "instruments"
    ]
    
    let suspiciousEnvVars = [
        "DYLD_INTERPOSE",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_APIS",
        "LLDB_DEBUGSERVER_PATH",
        "INSTRUMENTS_DT_CORE_SIMULATOR_PATH"
    ]
}
