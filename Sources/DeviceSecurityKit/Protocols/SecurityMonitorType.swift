import Foundation

public protocol SecurityMonitorType {
    
    /// Current security status
    var status: SecurityStatus { get }
    
    /// Interval between monitoring checks (default: 60 seconds)
    var monitoringInterval: TimeInterval { get set }
    
    /// Perform a one-time security check
    func performCheck() -> SecurityResult
    
    /// Quick check - returns true if device is secure
    func isSecure() -> Bool
    
    /// Start continuous monitoring
    func startMonitoring()
    
    /// Stop continuous monitoring
    func stopMonitoring()
    
    /// Update configuration
    func configure(_ configuration: DeviceSecurityConfiguration)
    
    /// Get current configuration
    func currentConfiguration() -> DeviceSecurityConfiguration
    
    /// Set handler for status changes
    @discardableResult
    func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self
    
    /// Set handler for threat detection
    @discardableResult
    func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self
}
