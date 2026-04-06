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

    // MARK: - Handlers (protected by stateQueue)
    private var _onStatusChange: ((SecurityStatus) -> Void)?
    private var _onThreatDetected: ((SecurityThreat) -> Void)?
    private var _screenRecordingProvider: ScreenRecordingProvider? = DefaultScreenRecordingProvider()

    // MARK: - Public Properties
    public var status: SecurityStatus {
        stateQueue.sync { _status }
    }

    public var monitoringInterval: TimeInterval = 60.0

    public var threatCallbackThrottleInterval: TimeInterval {
        get { stateQueue.sync { _threatCallbackThrottleInterval } }
        set { stateQueue.sync(flags: .barrier) { _threatCallbackThrottleInterval = newValue } }
    }

    public var screenRecordingProvider: ScreenRecordingProvider? {
        get { stateQueue.sync { _screenRecordingProvider } }
        set { stateQueue.sync(flags: .barrier) { _screenRecordingProvider = newValue } }
    }

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
        stateQueue.sync(flags: .barrier) { _onStatusChange = handler }
        return self
    }

    @discardableResult
    public func onThreatDetected(_ handler: @escaping (SecurityThreat) -> Void) -> Self {
        stateQueue.sync(flags: .barrier) { _onThreatDetected = handler }
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

    private func runChecks() {
        let result = gatherThreats()
        let pending = stateQueue.sync { applyResult(result) }
        firePending(pending)
    }

    private func gatherThreats() -> SecurityResult {
        let (cfg, provider) = stateQueue.sync { (configuration, _screenRecordingProvider) }
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
           let provider,
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

    private func firePending(_ pending: (statusChange: SecurityStatus?, newThreats: [SecurityThreat])) {
        guard pending.statusChange != nil || !pending.newThreats.isEmpty else { return }
        // Snapshot handlers under stateQueue to avoid a data race with concurrent setter calls.
        let (statusHandler, threatHandler) = stateQueue.sync { (_onStatusChange, _onThreatDetected) }
        DispatchQueue.main.async {
            if let status = pending.statusChange {
                statusHandler?(status)
            }
            for threat in pending.newThreats {
                threatHandler?(threat)
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
