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
        return UIScreen.main.isCaptured
#else
        return false
#endif
    }
}
