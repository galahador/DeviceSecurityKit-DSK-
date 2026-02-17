//
//  SecurityLoggerManager.swift
//  DeviceSecurityKit
//
//  Created by tBug on 17. 2. 2026..
//

import Foundation

public final class SecurityLoggerManager {
    public static let shared = SecurityLoggerManager()
    
    private var configuration: SecurityLoggerConfiguration = .default
    private let configurationQueue = DispatchQueue(label: "SecurityLogger.config", qos: .utility)
    
    private init() {}
    
    /// Configure the global logging behavior
    public func configure(_ configuration: SecurityLoggerConfiguration) {
        configurationQueue.sync {
            self.configuration = configuration
        }
    }
    
    /// Get current configuration (thread-safe)
    internal func currentConfiguration() -> SecurityLoggerConfiguration {
        return configurationQueue.sync {
            return configuration
        }
    }
}
