using System;

namespace JJones.IPASimulator.Model.MachO
{
    [Flags]
    public enum Flags : uint
    {
        NoUndefinedReferences = 0x1,
        IncrementalLink = 0x2,
        DynamicLink = 0x4,
        BindAtLoad = 0x8,
        Prebound = 0x10,
        SplitSegments = 0x20,
        LazyInit = 0x40,
        TwoLevel = 0x80,
        ForceFlat = 0x100,
        NoMultipleDefinitions = 0x200,
        NoFixPrebinding = 0x400,
        Prebindable = 0x800,
        AllModulesBound = 0x1000,
        SubsectionsViaSymbols = 0x2000,
        Canonical = 0x4000,
        WeakDefines = 0x8000,
        BindsToWeak = 0x10000,
        AllowStackExecution = 0x20000,
        RootSafe = 0x40000,
        SetUIDSafe = 0x80000,
        NoReexportedDynamicLibraries = 0x100000,
        Pie = 0x200000,
        DeadStrippableDynamicLibrary = 0x400000,
        HasTLVDescriptors = 0x800000,
        NoHeapExecution = 0x1000000,
        AppExtensionSafe = 0x2000000
    }
}
