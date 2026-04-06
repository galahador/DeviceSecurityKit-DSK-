import Foundation

public final class SecurityMonitor: SecurityMonitorType {

    // MARK: - Private Properties
    private var monitoringTimer: DispatchSourceTimer?
    private let timerQueue = DispatchQueue(label: "com.devicesecuritykit.monitor", qos: .userInitiated)
    private let stateQueue = DispatchQueue(label: "com.devicesecuritykit.monitor.state", qos: .userInitiated)

    private var configuration: DeviceSecurityConfiguration
    private var hasPerformedInitialCheck = false
    private var isMonitoring = false
    private var _status: SecurityStatus = .secure
    private var _previousThreats: Set<SecurityThreat> = []
    private var _lastThreatCallbackTime: [SecurityThreat: Date] = [:]
    private var _threatCallbackThrottleInterval: TimeInterval = 300

    // MARK: - Handlers
    private var onStatusChange: ((SecurityStatus) -> Void)?
    private var onThreatDetected: ((SecurityThreat) -> Void)?

    // MARK: - Public Properties
    public var status: SecurityStatus {
        stateQueue.sync { _status }
    }

    public var monitoringInterval: TimeInterval = 60.0

    public var threatCallbackThrottleInterval: TimeInterval {
        get { stateQueue.sync { _threatCallbackThrottleInterval } }
        set { stateQueue.sync(flags: .barrier) { _threatCallbackThrottleInterval = newValue } }
    }

    public var screenRecordingProvider: ScreenRecordingProvider?

    // MARK: - Initialization

    public init(configuration: DeviceSecurityConfiguration = .default) {
        self.configuration = configuration
    }

    deinit {
        stopMonitoring()
    }

    // MARK: - Configuration

    public func configure(_ configuration: DeviceSecurityConfiguration) {
        stateQueue.sync { self.configuration = configuration }

        if stateQueue.sync(execute: { isMonitoring }) {
            runChecks()
        }
    }

    public func currentConfiguration() -> DeviceSecurityConfiguration {
        stateQueue.sync { configuration }
    }

    // MARK: - Handlers

    @discardableResult
    public func onStatusChange(_ handler: @escaping (SecurityStatus) -> Void) -> Self {
        onStatusChange = handler
        return self
    }

    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        onThreatDetected = handler
        return self
    }

    // MARK: - Check Methods

    public func performCheck() -> SecurityResult {
        let result = gatherThreats()
        let pending = stateQueue.sync { applyResult(result) }
        firePending(pending)
        return result
    }

    public func isSecure() -> Bool {
        return performCheck().isSecure
    }

    // MARK: - Monitoring

    public func startMonitoring() {
        let alreadyRunning = stateQueue.sync { () -> Bool in
            if isMonitoring { return true }
            isMonitoring = true
            return false
        }
        guard !alreadyRunning else { return }

#if !DEBUG
        if stateQueue.sync(execute: { configuration.debuggerCheckEnabled }) {
            DebuggerDetector.startContinuousDenyAttach()
        }
#endif

        // Run an immediate first check so the caller isn't blind for the first interval
        runChecks()

        monitoringTimer = DispatchSource.makeTimerSource(queue: timerQueue)
        monitoringTimer?.schedule(
            deadline: .now() + monitoringInterval,
            repeating: monitoringInterval
        )

        monitoringTimer?.setEventHandler { [weak self] in
            self?.runChecks()
        }

        monitoringTimer?.resume()
    }

    public func stopMonitoring() {
        monitoringTimer?.cancel()
        monitoringTimer = nil
        stateQueue.sync { isMonitoring = false }
#if !DEBUG
        DebuggerDetector.stopContinuousDenyAttach()
#endif
    }

    // MARK: - Private

    /// Runs on timerQueue (background). Checks happen off the main thread, then
    /// state is updated under stateQueue and callbacks are dispatched to main.
    private func runChecks() {
        let result = gatherThreats()
        let pending = stateQueue.sync { applyResult(result) }
        firePending(pending)
    }

    /// Collects all active threats. May be called from any thread (no shared state touched).
    private func gatherThreats() -> SecurityResult {
        let cfg = stateQueue.sync { configuration }
        var threats: [SecurityThreat] = []

        if cfg.jailbreakCheckEnabled && JailbreakDetector.isJailbroken() {
            threats.append(.jailbreak)
        }
        if cfg.debuggerCheckEnabled && DebuggerDetector.isDebuggerAttached() {
            threats.append(.debugger)
        }
        #if !DEBUG
        if cfg.emulatorCheckEnabled && EmulatorDetector.isEmulator() {
            threats.append(.emulator)
        }
        #endif
        if cfg.reverseEngineeringCheckEnabled && ReverseEngineeringDetector.isReverseEngineered() {
            threats.append(.reverseEngineering)
        }
        if cfg.appIntegrityCheckEnabled && AppIntegrityDetector.isIntegrityCompromised(expectedTeamID: cfg.expectedTeamID) {
            threats.append(.appIntegrity)
        }
        if cfg.screenRecordingCheckEnabled,
           let provider = screenRecordingProvider,
           provider.isScreenBeingRecorded() {
            threats.append(.screenRecording)
        }
        if cfg.hookDetectionEnabled && HookDetector.isFunctionHooked() {
            threats.append(.hooked)
        }
        if cfg.pinningBypassDetectionEnabled && CertificatePinningDetector.isPinningBypassed() {
            threats.append(.pinningBypassed)
        }
        if cfg.vpnProxyDetectionEnabled && VPNProxyDetector.isVPNOrProxyActive() {
            threats.append(.vpnProxy)
        }

        return SecurityResult(threats: threats)
    }

    /// Applies a result to mutable state. Must be called inside stateQueue.sync.
    /// Returns the callbacks that should be fired after the lock is released.
    private func applyResult(_ result: SecurityResult) -> (statusChange: SecurityStatus?, newThreats: [SecurityThreat]) {
        let newStatus = mapToStatus(result)
        var statusChange: SecurityStatus?
        if newStatus != _status {
            _status = newStatus
            statusChange = newStatus
        }

        let currentThreats = Set(result.threats)
        let candidateThreats = currentThreats.subtracting(_previousThreats)
        _previousThreats = currentThreats
        hasPerformedInitialCheck = true
        
        let now = Date()
        let newThreats = Array(candidateThreats.filter { threat in
            guard let last = _lastThreatCallbackTime[threat] else { return true }
            return now.timeIntervalSince(last) >= _threatCallbackThrottleInterval
        })
        for threat in newThreats {
            _lastThreatCallbackTime[threat] = now
        }

        return (statusChange, newThreats)
    }

    /// Dispatches pending callbacks to the main queue.
    private func firePending(_ pending: (statusChange: SecurityStatus?, newThreats: [SecurityThreat])) {
        guard pending.statusChange != nil || !pending.newThreats.isEmpty else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let status = pending.statusChange {
                self.onStatusChange?(status)
            }
            for threat in pending.newThreats {
                self.onThreatDetected?(threat)
            }
        }
    }

    private func mapToStatus(_ result: SecurityResult) -> SecurityStatus {
        if result.isSecure { return .secure }

        if result.isJailbroken            { return .jailbroken }
        if result.isReverseEngineered     { return .reverseEngineered }
        if result.isAppIntegrityCompromised { return .appIntegrityCompromised }
        if result.isFunctionHooked        { return .hooked }
        if result.isPinningBypassed       { return .pinningBypassed }
        // High
        if result.isDebuggerAttached      { return .debuggerAttached }
        if result.isScreenRecorded        { return .screenRecording }
        // Medium
        if result.isEmulator              { return .emulator }
        if result.isVPNOrProxyActive      { return .vpnProxy }

        return .compromised
    }
}
