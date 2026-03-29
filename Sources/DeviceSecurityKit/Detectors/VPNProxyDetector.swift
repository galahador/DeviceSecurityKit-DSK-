import Foundation
import Darwin
import CFNetwork

public final class VPNProxyDetector {

    private static let logger = SecurityLogger.security(subsystem: "VPNProxyDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    public static func isVPNOrProxyActive() -> Bool {
        return checkVPNInterfaces() || checkProxyConfiguration()
    }

    private static func checkVPNInterfaces() -> Bool {
        let vpnPrefixes = [
            o.reveal([0xDF, 0xDE, 0xDF, 0xC4]),
            o.reveal([0xDA, 0xDA, 0xDA]),
            o.reveal([0xC3, 0xDA, 0xD9, 0xCF, 0xC9]),
            o.reveal([0xDE, 0xDF, 0xC4]),
        ]

        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return false }
        defer { freeifaddrs(ifaddr) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let flags = Int32(current.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0
            let isRunning = (flags & IFF_RUNNING) != 0
            guard isUp && isRunning else {
                cursor = current.pointee.ifa_next
                continue
            }
            if let namePtr = current.pointee.ifa_name {
                let name = String(cString: namePtr)
                for prefix in vpnPrefixes {
                    if name.hasPrefix(prefix) {
                        logger.warning("VPN interface detected: \(name)")
                        return true
                    }
                }
            }
            cursor = current.pointee.ifa_next
        }

        return false
    }

    // MARK: - Check 2: System Proxy Settings

    private static func checkProxyConfiguration() -> Bool {
        guard let rawSettings = CFNetworkCopySystemProxySettings() else { return false }
        let settings = rawSettings.takeRetainedValue() as NSDictionary

        let enableKeys = [
            o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xEF, 0xC4, 0xCB, 0xC8, 0xC6, 0xCF]),
            o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xF9, 0xEF, 0xC4, 0xCB, 0xC8, 0xC6, 0xCF]),
            o.reveal([0xF9, 0xE5, 0xE9, 0xE1, 0xF9, 0xEF, 0xC4, 0xCB, 0xC8, 0xC6, 0xCF]),
        ]

        let hostKeys = [
            o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xFA, 0xD8, 0xC5, 0xD2, 0xD3]),
            o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xF9, 0xFA, 0xD8, 0xC5, 0xD2, 0xD3]),
            o.reveal([0xF9, 0xE5, 0xE9, 0xE1, 0xF9, 0xFA, 0xD8, 0xC5, 0xD2, 0xD3]),
        ]

        for key in enableKeys {
            if (settings[key] as? Int) == 1 {
                logger.warning("Proxy enabled — key: \(key)")
                return true
            }
        }

        for key in hostKeys {
            if let host = settings[key] as? String, !host.isEmpty {
                logger.warning("Proxy host configured — key: \(key), host: \(host)")
                return true
            }
        }

        return false
    }
}
