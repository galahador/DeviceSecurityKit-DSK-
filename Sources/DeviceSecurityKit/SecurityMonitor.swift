import Foundation

public final class SecurityMonitor: SecurityMonitorType {

    // MARK: - Private Properties
    private var monitoringTimer: DispatchSourceTimer?
    private let timerQueue = DispatchQueue(label: "com.devicesecuritykit.monitor", qos: .userInitiated)

    private var configuration: DeviceSecurityConfiguration
    private var hasPerformedInitialCheck = false
    private var isMonitoring = false
    private var _status: SecurityStatus = .secure
    // Tracks threats from the last cycle so onThreatDetected only fires for new threats
    private var _previousThreats: Set<SecurityThreat> = []

    // MARK: - Handlers
    private var onStatusChange: ((SecurityStatus) -> Void)?
    private var onThreatDetected: ((SecurityThreat) -> Void)?

    // MARK: - Public Properties
    public var status: SecurityStatus {
        return _status
    }

    public var monitoringInterval: TimeInterval = 60.0

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
        self.configuration = configuration

        if isMonitoring {
            runChecks()
        }
    }

    public func currentConfiguration() -> DeviceSecurityConfiguration {
        return configuration
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
        var threats: [SecurityThreat] = []

        if configuration.jailbreakCheckEnabled && JailbreakDetector.isJailbroken() {
            threats.append(.jailbreak)
        }

        if configuration.debuggerCheckEnabled && DebuggerDetector.isDebuggerAttached() {
            threats.append(.debugger)
        }

        #if !DEBUG
        if configuration.emulatorCheckEnabled && EmulatorDetector.isEmulator() {
            threats.append(.emulator)
        }
        #endif

        if configuration.reverseEngineeringCheckEnabled && ReverseEngineeringDetector.isReverseEngineered() {
            threats.append(.reverseEngineering)
        }

        if configuration.appIntegrityCheckEnabled && AppIntegrityDetector.isIntegrityCompromised(expectedTeamID: configuration.expectedTeamID) {
            threats.append(.appIntegrity)
        }

        if configuration.screenRecordingCheckEnabled,
           let provider = screenRecordingProvider,
           provider.isScreenBeingRecorded() {
            threats.append(.screenRecording)
        }

        if configuration.hookDetectionEnabled && HookDetector.isFunctionHooked() {
            threats.append(.hooked)
        }

        if configuration.pinningBypassDetectionEnabled && CertificatePinningDetector.isPinningBypassed() {
            threats.append(.pinningBypassed)
        }

        if configuration.vpnProxyDetectionEnabled && VPNProxyDetector.isVPNOrProxyActive() {
            threats.append(.vpnProxy)
        }

        let result = SecurityResult(threats: threats)
        updateStatus(from: result)
        hasPerformedInitialCheck = true

        return result
    }

    public func isSecure() -> Bool {
        return performCheck().isSecure
    }

    // MARK: - Monitoring

    public func startMonitoring() {
        guard !isMonitoring else { return }

        isMonitoring = true

#if !DEBUG
        if configuration.debuggerCheckEnabled {
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
        isMonitoring = false
#if !DEBUG
        DebuggerDetector.stopContinuousDenyAttach()
#endif
    }

    // MARK: - Private

    private func runChecks() {
        DispatchQueue.main.async { [weak self] in
            _ = self?.performCheck()
        }
    }

    private func updateStatus(from result: SecurityResult) {
        let newStatus = mapToStatus(result)

        if newStatus != _status {
            _status = newStatus
            onStatusChange?(newStatus)
        }

        // Only fire onThreatDetected for threats that weren't present last cycle
        let currentThreats = Set(result.threats)
        let newThreats = currentThreats.subtracting(_previousThreats)
        for threat in newThreats {
            onThreatDetected?(threat)
        }
        _previousThreats = currentThreats
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
