import Foundation

public final class DSK {

    // MARK: - Singleton

    public static let shared = DSK()

    // MARK: - Private

    private let monitor = SecurityMonitor()

    private init() {}

    // MARK: - Configuration

    /// Override the default configuration. Call before `start()`.
    ///
    /// ```swift
    /// DSK.shared
    ///     .configure(
    ///         DeviceSecurityConfiguration.default
    ///             .withJailbreakCheck(false)   // disable jailbreak check
    ///             .withVPNProxyDetection(false) // corporate VPN — disable to avoid noise
    ///     )
    ///     .start()
    /// ```
    @discardableResult
    public func configure(_ configuration: DeviceSecurityConfiguration = .default) -> Self {
        monitor.configure(configuration)
        return self
    }

    /// Set how often the monitor re-checks in the background (default: 60 s).
    @discardableResult
    public func monitoringInterval(_ interval: TimeInterval) -> Self {
        monitor.monitoringInterval = interval
        return self
    }

    /// Inject a screen-recording provider. Required for screen-recording detection.
    ///
    /// ```swift
    /// struct MyScreenRecordingProvider: ScreenRecordingProvider {
    ///     func isScreenBeingRecorded() -> Bool {
    ///         UIScreen.main.isCaptured
    ///     }
    /// }
    ///
    /// DSK.shared
    ///     .screenRecordingProvider(MyScreenRecordingProvider())
    ///     .start()
    /// ```
    @discardableResult
    public func screenRecordingProvider(_ provider: ScreenRecordingProvider) -> Self {
        monitor.screenRecordingProvider = provider
        return self
    }

    // MARK: - Handlers

    /// Called whenever the security status changes (e.g. `.secure` → `.jailbroken`).
    @discardableResult
    public func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self {
        monitor.onStatusChange(handler)
        return self
    }

    /// Called once per new threat detected. Does not fire again for the same
    /// threat on subsequent monitoring cycles.
    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        monitor.onThreatDetected(handler)
        return self
    }

    // MARK: - Lifecycle

    /// Start continuous background monitoring.
    /// Performs an immediate check on call, then re-checks every `monitoringInterval` seconds.
    public func start() {
        monitor.startMonitoring()
    }

    /// Stop background monitoring.
    public func stop() {
        monitor.stopMonitoring()
    }

    // MARK: - Accessors

    /// Current security status (updated after each check cycle).
    public var status: SecurityStatus {
        return monitor.status
    }

    /// Run a one-shot security check and return the full result.
    @discardableResult
    public func performCheck() -> SecurityResult {
        return monitor.performCheck()
    }

    /// `true` when no threats are detected.
    public var isSecure: Bool {
        return monitor.status.isSecure
    }
}
