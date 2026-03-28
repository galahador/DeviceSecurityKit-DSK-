import Foundation
import Darwin
import MachO

public final class HookDetector {

    private static let logger = SecurityLogger.security(subsystem: "HookDetector")
    private static let o = StringObfuscator.shared

    // MARK: - Public

    /// Returns true if any security-critical C function has been hooked.
    public static func isFunctionHooked() -> Bool {
        return checkSystemFunctionOrigins()
            || checkFunctionPrologues()
    }

    private static func checkSystemFunctionOrigins() -> Bool {
        let functionNames = [
            o.reveal([0xD9, 0xD3, 0xD9, 0xC9, 0xDE, 0xC6]),
            o.reveal([0xCD, 0xCF, 0xDE, 0xCF, 0xC4, 0xDC]),
            o.reveal([0xCD, 0xCF, 0xDE, 0xDA, 0xC3, 0xCE]),
            o.reveal([0xCD, 0xCF, 0xDE, 0xDA, 0xDA, 0xC3, 0xCE]),
            o.reveal([0xF5, 0xCE, 0xD3, 0xC6, 0xCE, 0xF5, 0xC3, 0xC7, 0xCB, 0xCD, 0xCF, 0xF5, 0xC9, 0xC5, 0xDF, 0xC4, 0xDE]),
            o.reveal([0xF5, 0xCE, 0xD3, 0xC6, 0xCE, 0xF5, 0xCD, 0xCF, 0xDE, 0xF5, 0xC3, 0xC7, 0xCB, 0xCD, 0xCF, 0xF5, 0xC4, 0xCB, 0xC7, 0xCF])
        ]

        let systemPrefixes = [
            o.reveal([0x85, 0xDF, 0xD9, 0xD8, 0x85, 0xC6, 0xC3, 0xC8, 0x85]),
            o.reveal([0x85, 0xF9, 0xD3, 0xD9, 0xDE, 0xCF, 0xC7, 0x85, 0xE6, 0xC3, 0xC8, 0xD8, 0xCB, 0xD8, 0xD3, 0x85]),
            o.reveal([0x85, 0xE6, 0xC3, 0xC8, 0xD8, 0xCB, 0xD8, 0xD3, 0x85, 0xEB, 0xDA, 0xDA, 0xC6, 0xCF, 0x85])
        ]

        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        for name in functionNames {
            guard let sym = dlsym(handle, name) else { continue }

            var info = Dl_info()
            guard dladdr(sym, &info) != 0, let fname = info.dli_fname else {
                logger.warning("Hook check: could not resolve image for function — treating as suspicious")
                return true
            }

            let imagePath = String(cString: fname)
            if !systemPrefixes.contains(where: { imagePath.hasPrefix($0) }) {
                logger.warning("Hook detected: function redirected to non-system image: \(imagePath)")
                return true
            }
        }

        return false
    }

    private static func checkFunctionPrologues() -> Bool {
#if arch(arm64)
        guard let handle = dlopen(nil, RTLD_NOW) else { return false }
        defer { dlclose(handle) }

        // Obfuscated: "sysctl", "getenv"
        let targets = [
            o.reveal([0xD9, 0xD3, 0xD9, 0xC9, 0xDE, 0xC6]),
            o.reveal([0xCD, 0xCF, 0xDE, 0xCF, 0xC4, 0xDC])
        ]

        for name in targets {
            guard let sym = dlsym(handle, name) else { continue }

            let instructions = UnsafeRawPointer(sym).assumingMemoryBound(to: UInt32.self)
            let first  = instructions.pointee
            let second = instructions.advanced(by: 1).pointee

            // Frida trampoline: LDR X16, #8 + BR X16
            if first == 0x58000050 && second == 0xD61F0200 {
                logger.warning("Frida inline hook trampoline detected on: \(name)")
                return true
            }

            // Generic unconditional branch at function start
            if (first & 0xFC000000) == 0x14000000 {
                logger.warning("Suspicious unconditional branch at start of: \(name)")
                return true
            }
        }
#endif
        return false
    }
}
