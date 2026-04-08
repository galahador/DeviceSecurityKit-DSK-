import Foundation

/// An automatic response that fires when a matching threat is detected.
///
/// Register countermeasures via ``DSK/countermeasure(for:throttled:action:)``,
/// ``DSK/countermeasure(forMinimumSeverity:throttled:action:)``, or
/// ``DSK/countermeasure(throttled:action:)``.
///
/// **Threading:** actions fire synchronously on the queue that performs the
/// security check — the timer queue for periodic monitoring, or the caller's
/// thread for ``DSK/performCheck()``. If your action touches UIKit, dispatch
/// to the main queue inside the closure.
///
/// **Memory:** actions are stored as escaping closures on the ``DSK/shared``
/// singleton. Use `[weak self]` to avoid permanently retaining objects.
///
/// **Example:**
/// ```swift
/// DSK.shared
///     .countermeasure(for: .fridaDetected) { [weak self] _ in
///         self?.sessionManager.invalidateAll()
///     }
///     .countermeasure(forMinimumSeverity: .critical, throttled: false) { _ in
///         // fires on every detection cycle, not just the first
///         exit(1)
///     }
///     .start()
/// ```
public struct Countermeasure: Equatable {

    // MARK: - Trigger
    public enum Trigger {
        case threat(SecurityThreat)
        case minimumSeverity(ThreatSeverity)
        case anyThreat
    }

    // MARK: - Properties
    public let id: UUID
    public let trigger: Trigger
    public let throttled: Bool
    public let action: (SecurityThreat) -> Void

    // MARK: - Init
    public init(
        trigger: Trigger,
        throttled: Bool = true,
        action: @escaping (SecurityThreat) -> Void
    ) {
        if case .threat(let t) = trigger {
            assert(t != .noThreat, "Countermeasures cannot target .noThreat — it is never emitted.")
        }
        self.id        = UUID()
        self.trigger   = trigger
        self.throttled = throttled
        self.action    = action
    }

    // MARK: - Equatable
    public static func == (lhs: Countermeasure, rhs: Countermeasure) -> Bool {
        lhs.id == rhs.id
    }

    // MARK: - Internal

    internal func matches(_ threat: SecurityThreat) -> Bool {
        switch trigger {
        case .threat(let t):          return threat == t
        case .minimumSeverity(let m): return threat.severity >= m
        case .anyThreat:              return true
        }
    }
}
