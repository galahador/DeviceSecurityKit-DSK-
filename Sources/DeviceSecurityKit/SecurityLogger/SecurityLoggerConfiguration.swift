//
//  SecurityLoggerConfiguration.swift
//  DeviceSecurityKit
//
//  Created by tBug on 17. 2. 2026..
//

import Foundation
public struct SecurityLoggerConfiguration {
    public let enableLogging: Bool
    public let logLevel: SecurityLogger.LogLevel
    public let enableConsoleOutput: Bool
    public let enableSystemLogging: Bool
    public let customOutputHandler: ((String, SecurityLogger.LogLevel) -> Void)?
    
    public init(
        enableLogging: Bool = true,
        logLevel: SecurityLogger.LogLevel = .debug,
        enableConsoleOutput: Bool = true,
        enableSystemLogging: Bool = true,
        customOutputHandler: ((String, SecurityLogger.LogLevel) -> Void)? = nil
    ) {
        self.enableLogging = enableLogging
        self.logLevel = logLevel
        self.enableConsoleOutput = enableConsoleOutput
        self.enableSystemLogging = enableSystemLogging
        self.customOutputHandler = customOutputHandler
    }
    
    public static let `default` = SecurityLoggerConfiguration()
    
    public static let silent = SecurityLoggerConfiguration(
        enableLogging: false,
        logLevel: .error,
        enableConsoleOutput: false,
        enableSystemLogging: false
    )
    
    public static let production = SecurityLoggerConfiguration(
        enableLogging: true,
        logLevel: .warning,
        enableConsoleOutput: false,
        enableSystemLogging: true
    )
}
