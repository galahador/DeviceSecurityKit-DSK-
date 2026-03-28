import Foundation

struct JailbreakListOptions {
    let suspiciousVars = [
        "_MSSafeMode",
        "_SafeMode",

        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",

        "SUBSTRATE_DYLIB_PATH",
        "SUBSTRATE_INSERT_LIBRARIES",
        "SUBSTITUTE_DYLIB_PATH",

        "LIBHOOKER_PLIST",
        "CYCRIPT_DYLIB",

        "FRIDA",
        "FRIDA_DYLIB_PATH"
    ]

    let suspiciousPaths = [
        // Package managers
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",

        // Jailbreak apps
        "/Applications/checkra1n.app",
        "/Applications/unc0ver.app",
        "/Applications/Taurine.app",
        "/Applications/Odyssey.app",
        "/Applications/dopamine.app",
        "/Applications/palera1n.app",

        // Tweak loaders
        "/Library/MobileSubstrate",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",

        "/usr/lib/libsubstitute.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/substitute-loader.dylib",
        "/usr/lib/substitute-inserter.dylib",
        "/usr/lib/TweakInject",

        // Rootless jailbreaks
        "/var/containers/Bundle/tweaksupport",
        "/var/jb",
        "/var/checkra1n",
        "/var/palera1n",

        // Package system
        "/var/lib/cydia",
        "/private/var/lib/cydia",
        "/var/lib/apt",
        "/private/var/lib/apt",
        "/etc/apt",

        // Preboot (dopamine / palera1n rootless)
        "/private/preboot",

        // Daemons / prefs
        "/Library/PreferenceBundles",
        "/Library/LaunchDaemons",

        // Instrumentation
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
        "dopamine://",
        "palera1n://"
    ]

    let testPaths = [
        "/private/jb_test.txt",
        "/var/jb/jb_test.txt",
        "/usr/bin/jb_test.txt"
    ]
}
