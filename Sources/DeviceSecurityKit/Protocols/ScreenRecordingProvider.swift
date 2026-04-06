import Foundation
#if canImport(UIKit)
import UIKit
#endif

public protocol ScreenRecordingProvider {
    func isScreenBeingRecorded() -> Bool
}

public struct DefaultScreenRecordingProvider: ScreenRecordingProvider {
    public init() {}

    public func isScreenBeingRecorded() -> Bool {
#if canImport(UIKit)
        // UIScreen.main is deprecated on iOS 16+ but remains correct and thread-safe
        // for this read-only property check on iOS 15+.
        return UIScreen.main.isCaptured
#else
        return false
#endif
    }
}
