import Foundation

/// XOR-based string obfuscator that decodes threat-signature strings at runtime.
///
/// Sensitive strings (library names, environment variable names, bundle paths) are
/// stored as XOR-encoded byte arrays so they do not appear as plaintext in the
/// compiled binary. A static analysis tool running `strings` on the binary will
/// see only non-printable bytes instead of recognisable names like "FridaGadget"
/// or "DYLD_INSERT_LIBRARIES".
///
/// Usage — decoding:
/// ```swift
/// let name = StringObfuscator.shared.reveal([0xEC, 0xD8, 0xC3, 0xCE, 0xCB, 0xED, 0xCB, 0xCE, 0xCD, 0xCF, 0xDE])
/// // name == "FridaGadget"
/// ```
///
/// Usage — generating new encoded constants (DEBUG builds only):
/// ```swift
/// let encoded = StringObfuscator.shared.conceal("NewLibraryName")
/// print(encoded) // paste the resulting array as a new constant
/// ```
internal struct StringObfuscator {

    // MARK: - Shared instance

    internal static let shared = StringObfuscator(key: 0xAA)

    // MARK: - Private

    private let key: UInt8

    private init(key: UInt8) {
        self.key = key
    }

    // MARK: - Decoding

    /// Decodes an XOR-obfuscated byte array back into a plain string.
    /// Returns an empty string if the bytes are not valid UTF-8.
    internal func reveal(_ encoded: [UInt8]) -> String {
        let decoded = encoded.map { $0 ^ key }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    // MARK: - Encoding (development only)

#if DEBUG
    /// Encodes a plain string into an XOR-obfuscated byte array.
    /// Use this during development to produce new encoded constants, then
    /// remove the call and paste the resulting array into the appropriate list file.
    internal func conceal(_ string: String) -> [UInt8] {
        return string.utf8.map { $0 ^ key }
    }
#endif
}
