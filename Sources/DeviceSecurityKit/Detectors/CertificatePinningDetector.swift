import Foundation
import Darwin
import CFNetwork

public final class CertificatePinningDetector {

    private static let logger = SecurityLogger.security(subsystem: "CertificatePinningDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    /// Returns true if certificate pinning appears to have been bypassed.
    ///
    /// Three checks are run:
    /// 1. Security.framework functions are verified via dladdr — hooks indicate active bypass.
    /// 2. Known SSL bypass dylibs are scanned in the loaded image list.
    /// 3. An HTTP/HTTPS proxy is checked in system settings (a common MITM setup).
    ///
    /// - Note: Proxy detection (#3) may produce false positives on corporate or VPN networks.
    public static func isPinningBypassed() -> Bool {
        return checkSecurityFrameworkIntegrity()
            || checkSSLBypassLibraries()
            || checkProxyConfiguration()
    }

    // MARK: - Check 1: Security.framework function integrity
    //
    // Resolves pinning-critical functions via dlsym and uses dladdr to verify
    // they still live inside Security.framework. A hook redirecting these
    // functions is the most direct form of pinning bypass.
    //
    // Catches: Frida SSL unpinning scripts, SSLKillSwitch-style hooks on
    // SecTrustEvaluate / SecTrustEvaluateWithError / SSLHandshake.

    private static func checkSecurityFrameworkIntegrity() -> Bool {
        // Obfuscated function names (key 0xAA). Plain-text:
        // "SecTrustEvaluate", "SecTrustEvaluateWithError", "SSLHandshake"
        let functions = [
            o.reveal([0xF9, 0xCF, 0xC9, 0xFE, 0xD8, 0xDF, 0xD9, 0xDE, 0xEF, 0xDC, 0xCB, 0xC6, 0xDF, 0xCB, 0xDE, 0xCF]),
            o.reveal([0xF9, 0xCF, 0xC9, 0xFE, 0xD8, 0xDF, 0xD9, 0xDE, 0xEF, 0xDC, 0xCB, 0xC6, 0xDF, 0xCB, 0xDE, 0xCF,
                      0xFD, 0xC3, 0xDE, 0xC2, 0xEF, 0xD8, 0xD8, 0xC5, 0xD8]),
            o.reveal([0xF9, 0xF9, 0xE6, 0xE2, 0xCB, 0xC4, 0xCE, 0xD9, 0xC2, 0xCB, 0xC1, 0xCF])
        ]

        // Obfuscated expected path prefix. Plain-text:
        // "/System/Library/Frameworks/Security.framework"
        let expectedPrefix = o.reveal([
            0x85, 0xF9, 0xD3, 0xD9, 0xDE, 0xCF, 0xC7, 0x85, 0xE6, 0xC3, 0xC8, 0xD8, 0xCB, 0xD8, 0xD3, 0x85,
            0xEC, 0xD8, 0xCB, 0xC7, 0xCF, 0xDD, 0xC5, 0xD8, 0xC1, 0xD9, 0x85, 0xF9, 0xCF, 0xC9, 0xDF, 0xD8,
            0xC3, 0xDE, 0xD3, 0x84, 0xCC, 0xD8, 0xCB, 0xC7, 0xCF, 0xDD, 0xC5, 0xD8, 0xC1
        ])

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        for name in functions {
            guard let sym = dlsym(handle, name) else { continue }

            var info = Dl_info()
            guard dladdr(sym, &info) != 0, let fname = info.dli_fname else {
                logger.warning("Pinning check: cannot resolve image for \(name) — treating as suspicious")
                return true
            }

            let imagePath = String(cString: fname)
            if !imagePath.hasPrefix(expectedPrefix) {
                logger.warning("Pinning bypass: \(name) redirected to: \(imagePath)")
                return true
            }
        }

        return false
    }

    // MARK: - Check 2: SSL bypass library detection
    //
    // Scans loaded dylibs for libraries known to disable or bypass SSL pinning.
    // Catches: SSLKillSwitch2, ssl-kill-switch, AlwaysTrustSSL.

    private static func checkSSLBypassLibraries() -> Bool {
        // Obfuscated bypass library names (key 0xAA). Plain-text:
        // "SSLKillSwitch2", "ssl-kill-switch", "AlwaysTrustSSL"
        let bypassLibraries = [
            o.reveal([0xF9, 0xF9, 0xE6, 0xE1, 0xC3, 0xC6, 0xC6, 0xF9, 0xDD, 0xC3, 0xDE, 0xC9, 0xC2, 0x98]),
            o.reveal([0xD9, 0xD9, 0xC6, 0x87, 0xC1, 0xC3, 0xC6, 0xC6, 0x87, 0xD9, 0xDD, 0xC3, 0xDE, 0xC9, 0xC2]),
            o.reveal([0xEB, 0xC6, 0xDD, 0xCB, 0xD3, 0xD9, 0xFE, 0xD8, 0xDF, 0xD9, 0xDE, 0xF9, 0xF9, 0xE6])
        ]

        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: rawName).lowercased()

            for lib in bypassLibraries {
                if imageName.contains(lib.lowercased()) {
                    logger.warning("SSL bypass library detected: \(imageName)")
                    return true
                }
            }
        }

        return false
    }

    // MARK: - Check 3: Proxy configuration
    //
    // An active HTTP/HTTPS proxy is a common indicator of a MITM setup
    // (Charles Proxy, Burp Suite) used to intercept SSL-pinned traffic.
    //
    // ⚠️ False positives: corporate networks, VPNs, and developer proxies will
    // also trigger this. Treat as a signal, not a definitive bypass indicator.

    private static func checkProxyConfiguration() -> Bool {
        guard let rawSettings = CFNetworkCopySystemProxySettings() else { return false }
        let settings = rawSettings.takeRetainedValue() as NSDictionary

        // Obfuscated proxy setting keys (key 0xAA). Plain-text:
        // "HTTPEnable", "HTTPSEnable"
        let httpKey  = o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xEF, 0xC4, 0xCB, 0xC8, 0xC6, 0xCF])
        let httpsKey = o.reveal([0xE2, 0xFE, 0xFE, 0xFA, 0xF9, 0xEF, 0xC4, 0xCB, 0xC8, 0xC6, 0xCF])

        let httpEnabled  = (settings[httpKey]  as? Int) == 1
        let httpsEnabled = (settings[httpsKey] as? Int) == 1

        if httpEnabled || httpsEnabled {
            logger.warning("HTTP/HTTPS proxy detected — possible MITM setup")
            return true
        }

        return false
    }
}
