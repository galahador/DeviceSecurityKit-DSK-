import Foundation

public final class DSK {

    // MARK: - Singleton

    public static let shared = DSK()

    // MARK: - Private

    private let monitor = SecurityMonitor()

    private init() {}

    // MARK: - Configuration

    @discardableResult
    public func configure(_ configuration: DeviceSecurityConfiguration = .default) -> Self {
        monitor.configure(configuration)
        return self
    }

    @discardableResult
    public func monitoringInterval(_ interval: TimeInterval) -> Self {
        monitor.monitoringInterval = interval
        return self
    }

    @discardableResult
    public func screenRecordingProvider(_ provider: ScreenRecordingProvider) -> Self {
        monitor.screenRecordingProvider = provider
        return self
    }

    // MARK: - Handlers

    @discardableResult
    public func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self {
        monitor.onStatusChange(handler)
        return self
    }

    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        monitor.onThreatDetected(handler)
        return self
    }

    // MARK: - Lifecycle

    public func start() {
        monitor.startMonitoring()
    }

    public func stop() {
        monitor.stopMonitoring()
    }

    // MARK: - Accessors

    public var status: SecurityStatus {
        return monitor.status
    }

    @discardableResult
    public func performCheck() -> SecurityResult {
        return monitor.performCheck()
    }

    public var isSecure: Bool {
        return monitor.status.isSecure
    }
}
