import Foundation
import Darwin
import CFNetwork
import MachO

public final class CertificatePinningDetector {

    private static let logger = SecurityLogger.security(subsystem: "CertificatePinningDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public
    public static func isPinningBypassed() -> Bool {
        return checkSecurityFrameworkIntegrity()
            || checkSSLBypassLibraries()
            || checkProxyConfiguration()
    }

    private static func checkSecurityFrameworkIntegrity() -> Bool {
        let functions = [
            o.reveal([0xF9, 0xCF, 0xC9, 0xFE, 0xD8, 0xDF, 0xD9, 0xDE, 0xEF, 0xDC, 0xCB, 0xC6, 0xDF, 0xCB, 0xDE, 0xCF]),
            o.reveal([0xF9, 0xCF, 0xC9, 0xFE, 0xD8, 0xDF, 0xD9, 0xDE, 0xEF, 0xDC, 0xCB, 0xC6, 0xDF, 0xCB, 0xDE, 0xCF,
                      0xFD, 0xC3, 0xDE, 0xC2, 0xEF, 0xD8, 0xD8, 0xC5, 0xD8]),
            o.reveal([0xF9, 0xF9, 0xE6, 0xE2, 0xCB, 0xC4, 0xCE, 0xD9, 0xC2, 0xCB, 0xC1, 0xCF])
        ]

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

    private static func checkSSLBypassLibraries() -> Bool {
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

    private static func checkProxyConfiguration() -> Bool {
        guard let rawSettings = CFNetworkCopySystemProxySettings() else { return false }
        let settings = rawSettings.takeRetainedValue() as NSDictionary

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
