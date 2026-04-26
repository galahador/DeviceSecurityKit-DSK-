//
//  ReverseEngineeringDetector.swift
//  DeviceSecurityKit
//
//  Created by Petar Lemajic on 26/04/2026.
//

import Foundation
import Darwin
import MachO

public final class ReverseEngineeringDetector {
    
    // MARK: - Private Properties
    private static var reverseEngineeringListsOptions = ReverseEngineeringListsOptions()
    
    // MARK: - Public
    public static func isReverseEngineered() -> Bool {
        return checkSuspiciousLibraries()
        || checkEnvironmentVariables()
        || checkCodeIntegrity()
    }
    
    // MARK: - Private
    private static func checkSuspiciousLibraries() -> Bool {
        for libraryName in reverseEngineeringListsOptions.suspiciousLibraries {
            if checkIfLibraryLoaded(libraryName) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkIfLibraryLoaded(_ libraryName: String) -> Bool {
        let maxImages = _dyld_image_count()
        
        for i in 0..<maxImages {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            
            if name.lowercased().contains(libraryName.lowercased()) {
                return true
            }
        }
        
        return false
    }
    
    private static func checkEnvironmentVariables() -> Bool {
#if DEBUG
        return false
#else
        for varName in reverseEngineeringListsOptions.suspiciousVars {
            if let value = getenv(varName), String(cString: value).count > 0 {
                return true
            }
        }
        return false
#endif
    }
    
    private static let validBundlePrefixes: [String] = {
        let o = StringObfuscator.shared
        return [
            o.reveal([0x85, 0xDC, 0xCB, 0xD8, 0x85, 0xC9, 0xC5, 0xC4, 0xDE, 0xCB, 0xC3, 0xC4, 0xCF, 0xD8, 0xD9, 0x85, 0xE8, 0xDF, 0xC4, 0xCE, 0xC6, 0xCF, 0x85, 0xEB, 0xDA, 0xDA, 0xC6, 0xC3, 0xC9, 0xCB, 0xDE, 0xC3, 0xC5, 0xC4, 0x85]),
            o.reveal([0x85, 0xDA, 0xD8, 0xC3, 0xDC, 0xCB, 0xDE, 0xCF, 0x85, 0xDC, 0xCB, 0xD8, 0x85, 0xC9, 0xC5, 0xC4, 0xDE, 0xCB, 0xC3, 0xC4, 0xCF, 0xD8, 0xD9, 0x85, 0xE8, 0xDF, 0xC4, 0xCE, 0xC6, 0xCF, 0x85, 0xEB, 0xDA, 0xDA, 0xC6, 0xC3, 0xC9, 0xCB, 0xDE, 0xC3, 0xC5, 0xC4, 0x85])
        ]
    }()
    
    private static func checkCodeIntegrity() -> Bool {
        guard let executablePath = Bundle.main.executablePath else { return false }
        
        guard FileManager.default.fileExists(atPath: executablePath) else { return true }
        
#if os(iOS) && !targetEnvironment(simulator)
        let bundlePath = Bundle.main.bundlePath
        if !validBundlePrefixes.contains(where: { bundlePath.hasPrefix($0) }) {
            return true
        }
#endif
        
        return false
    }
}
