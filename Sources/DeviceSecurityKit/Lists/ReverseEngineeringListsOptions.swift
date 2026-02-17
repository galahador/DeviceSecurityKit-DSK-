import Foundation

struct ReverseEngineeringListsOptions {
    let suspiciousLibraries = [
        "FridaGadget",
        "frida-agent",
        "MobileSubstrate",
        "SubstrateInserter",
        "substitute-inserter",
        "libhooker",
        "Shadow",
        "ABypass",
        "Liberty",
        "Choicy",
        "vnodebypass"
    ]

    let suspiciousVars = [
        "_MSSafeMode",
        "_SafeMode"
    ]
}
