//
//  VPNProxyDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import CFNetwork
import NetworkExtension

public final class VPNProxyDetector {

    private static let logger = SecurityLogger.security(subsystem: "VPNProxyDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    public static func isVPNOrProxyActive() -> Bool {
        return checkVPNInterfaces() || checkProxyConfiguration()
    }

    private static func checkVPNInterfaces() -> Bool {
        let status = NEVPNManager.shared().connection.status
        if status == .connected || status == .connecting || status == .reasserting {
            logger.warning("VPN connection detected via NEVPNManager: status \(status.rawValue)")
            return true
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
