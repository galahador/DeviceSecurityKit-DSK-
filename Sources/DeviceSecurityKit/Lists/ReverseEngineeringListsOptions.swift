import Foundation

struct ReverseEngineeringListsOptions {
    let suspiciousLibraries = [
        // Frida instrumentation framework
        "FridaGadget",
        "frida-agent",
        // Substrate / hooking loaders
        "MobileSubstrate",
        "SubstrateInserter",
        "substitute-inserter",
        "substitute-loader",
        "libhooker",
        // TweakInject (rootless substrate replacement)
        "TweakInject",
        // Jailbreak bypass / detection evasion
        "Shadow",
        "ABypass",
        "Liberty",
        "vnodebypass",
        // Tweak managers
        "Choicy",
        // Network interception
        "SSLKillSwitch",
        // Runtime inspection / scripting
        "Cycript",
        // UI inspection / modification
        "libFLEX"
    ]

    let suspiciousVars = [
        "_MSSafeMode",
        "_SafeMode",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH"
    ]
}
