import Foundation

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
