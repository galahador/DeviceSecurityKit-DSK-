import Foundation

struct JailbreakListOptions {
    let suspiciousVars = [
        "_MSSafeMode",
        "_SafeMode",
        "SUBSTRATE_DYLIB_PATH",
        "SUBSTITUTE_DYLIB_PATH",
        "CYCRIPT_DYLIB",
        "FRIDA_DYLIB_PATH",
        "MS_DYLIB_PATH",
        "SUBSTRATE_INSERT_LIBRARIES"
    ]

    let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Applications/checkra1n.app",
        "/Applications/unc0ver.app",
        "/Applications/Taurine.app",
        "/Applications/Odyssey.app",
        "/Applications/dopamine.app",
        "/Applications/palera1n.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/",
        "/var/lib/cydia",
        "/private/var/lib/cydia",
        "/private/var/lib/apt",
        "/etc/apt",
        "/var/jb",
        "/var/checkra1n",
        "/var/palera1n",
        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/TweakInject",
        "/usr/sbin/frida-server"
    ]

    let urlSchemes = [
        "cydia://",
        "sileo://",
        "zbra://",
        "filza://",
        "undecimus://",
        "checkra1n://",
        "taurine://",
        "odyssey://",
        "dopamine://"
    ]

    let testPaths = [
        "/private/jb_test.txt"
    ]

    let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/checkra1n.app",
        "/Applications/unc0ver.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/var/lib/cydia",
        "/private/var/lib/cydia",
        "/var/jb",
        "/var/checkra1n",
        "/usr/lib/libsubstitute.dylib"
    ]
}
