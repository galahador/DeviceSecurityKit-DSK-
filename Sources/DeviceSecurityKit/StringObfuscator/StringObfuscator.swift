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

    internal func reveal(_ encoded: [UInt8]) -> String {
        let decoded = encoded.map { $0 ^ key }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    // MARK: - Encoding (development only)

#if DEBUG
    internal func conceal(_ string: String) -> [UInt8] {
        return string.utf8.map { $0 ^ key }
    }
#endif
}
