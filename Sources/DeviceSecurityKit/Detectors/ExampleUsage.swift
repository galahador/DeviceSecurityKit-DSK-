import Foundation

// MARK: - Example: How to use SecurityLogger from your app

/// Example of configuring SecurityLogger from the importing app
class AppSecurityConfiguration {
    
    /// Configure SecurityLogger when your app starts
    static func configureSecurityLogging() {
        
        // Option 1: Silent mode (no logging at all)
        // SecurityLoggerManager.shared.configure(.silent)
        
        // Option 2: Production mode (warnings and errors only, system logging)
        // SecurityLoggerManager.shared.configure(.production)
        
        // Option 3: Custom configuration
        let customConfig = SecurityLoggerConfiguration(
            enableLogging: true,
            logLevel: .info,
            enableConsoleOutput: true,
            enableSystemLogging: true,
            customOutputHandler: { message, level in
                // Custom handling - send to analytics, file, etc.
                print("CUSTOM LOG: \(message)")
                
                // Example: Send critical errors to crash reporting
                if level == .error {
                    // CrashReporter.log(message)
                }
            }
        )
        
        SecurityLoggerManager.shared.configure(customConfig)
    }
    
    /// Example of using DebuggerDetector with configured logging
    static func performSecurityCheck() {
        // The library will use the global configuration you set above
        let isDebuggerPresent = DebuggerDetector.isDebuggerAttached()
        
        if isDebuggerPresent {
            // Handle debugger detection
            print("⚠️ Debugger detected!")
            // Take appropriate action (exit, disable features, etc.)
        }
    }
}

// MARK: - Example: App Delegate Integration

/*
class AppDelegate: UIApplicationDelegate {
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        // Configure security logging first
        AppSecurityConfiguration.configureSecurityLogging()
        
        // Then perform security checks
        AppSecurityConfiguration.performSecurityCheck()
        
        return true
    }
}
*/

// MARK: - Example: SwiftUI App Integration

/*
@main
struct MySecurityApp: App {
    
    init() {
        // Configure security logging when app starts
        AppSecurityConfiguration.configureSecurityLogging()
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onAppear {
                    // Perform security checks
                    AppSecurityConfiguration.performSecurityCheck()
                }
        }
    }
}
*/

// MARK: - Example: Different Logging Configurations

extension SecurityLoggerConfiguration {
    
    /// Development configuration - verbose logging
    static let development = SecurityLoggerConfiguration(
        enableLogging: true,
        logLevel: .debug,
        enableConsoleOutput: true,
        enableSystemLogging: false
    )
    
    /// Testing configuration - minimal logging
    static let testing = SecurityLoggerConfiguration(
        enableLogging: true,
        logLevel: .error,
        enableConsoleOutput: false,
        enableSystemLogging: false
    )
    
    /// Analytics configuration - custom handler for metrics
    static func analytics(handler: @escaping (String, SecurityLogger.LogLevel) -> Void) -> SecurityLoggerConfiguration {
        return SecurityLoggerConfiguration(
            enableLogging: true,
            logLevel: .warning,
            enableConsoleOutput: false,
            enableSystemLogging: false,
            customOutputHandler: handler
        )
    }
}