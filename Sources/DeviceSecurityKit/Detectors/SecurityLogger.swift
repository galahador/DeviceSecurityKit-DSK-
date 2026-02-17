import Foundation

#if canImport(os.log)
import os.log
#endif

/// A custom logger designed for security-related operations with cross-platform compatibility
public final class SecurityLogger {
    
    // MARK: - Public Types
    
    public enum LogLevel: String, CaseIterable {
        case debug = "🔍 DEBUG"
        case info = "ℹ️ INFO"
        case warning = "⚠️ WARNING"
        case error = "❌ ERROR"
        
        internal var shouldLog: Bool {
            #if DEBUG
            return true
            #else
            // In release builds, only log warnings and errors for security
            return self == .warning || self == .error
            #endif
        }
        
        internal var osLogType: OSLogType {
            #if canImport(os.log)
            switch self {
            case .debug:
                return .debug
            case .info:
                return .info
            case .warning:
                return .default
            case .error:
                return .error
            }
            #else
            return .default
            #endif
        }
    }
    
    // MARK: - Private Properties
    
    private let subsystem: String
    private let category: String
    private let dateFormatter: DateFormatter
    
    #if canImport(os.log)
    @available(iOS 10.0, *)
    private lazy var osLog: OSLog = {
        return OSLog(subsystem: subsystem, category: category)
    }()
    #endif
    
    // MARK: - Initialization
    
    public init(subsystem: String, category: String) {
        self.subsystem = subsystem
        self.category = category
        self.dateFormatter = SecurityLogger.createDateFormatter()
    }
    
    // MARK: - Public Methods
    
    /// Log a message with specified level and context information
    public func log(
        _ message: String,
        level: LogLevel = .info,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        guard level.shouldLog else { return }
        
        let logMessage = formatLogMessage(
            message: message,
            level: level,
            file: file,
            function: function,
            line: line
        )
        
        outputLog(logMessage, level: level)
    }
    
    /// Log a debug message (only in DEBUG builds)
    public func debug(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .debug, file: file, function: function, line: line)
    }
    
    /// Log an informational message
    public func info(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .info, file: file, function: function, line: line)
    }
    
    /// Log a warning message
    public func warning(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .warning, file: file, function: function, line: line)
    }
    
    /// Log an error message
    public func error(
        _ message: String,
        file: String = #file,
        function: String = #function,
        line: Int = #line
    ) {
        log(message, level: .error, file: file, function: function, line: line)
    }
    
    // MARK: - Private Methods
    
    private static func createDateFormatter() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }
    
    private func formatLogMessage(
        message: String,
        level: LogLevel,
        file: String,
        function: String,
        line: Int
    ) -> String {
        let fileName = URL(fileURLWithPath: file).lastPathComponent
        let timestamp = dateFormatter.string(from: Date())
        
        return "[\(timestamp)] \(level.rawValue) [\(subsystem):\(category)] \(fileName):\(line) \(function) - \(message)"
    }
    
    private func outputLog(_ message: String, level: LogLevel) {
        #if DEBUG
        // In debug builds, always print to console for immediate visibility
        print(message)
        #else
        // In release builds, use system logging when available
        if #available(iOS 10.0, *) {
            #if canImport(os.log)
            os_log("%{public}@", log: osLog, type: level.osLogType, message)
            #else
            NSLog("%@", message)
            #endif
        } else {
            NSLog("%@", message)
        }
        #endif
    }
}

// MARK: - Convenience Factory

public extension SecurityLogger {
    /// Create a logger for security-related operations
    static func security(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Security")
    }
    
    /// Create a logger for debug-related operations
    static func debug(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Debug")
    }
    
    /// Create a logger for monitoring operations
    static func monitor(subsystem: String) -> SecurityLogger {
        return SecurityLogger(subsystem: subsystem, category: "Monitor")
    }
}