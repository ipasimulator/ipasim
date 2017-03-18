using System;

namespace JJones.IPASimulator.Model.MachO
{
    [Flags]
    public enum SectionAttributes : uint
    {
        None,
        PureInstructions = 0x80000000,
        NoToc = 0x40000000,
        StripStaticSyms = 0x20000000,
        NoDeadStrip = 0x10000000,
        LiveSupport = 0x08000000,
        SelfModifyingCode = 0x04000000,
        Debug = 0x02000000,
        SomeInstructions = 0x00000400,
        ExtReloc = 0x00000200,
        LocReloc = 0x00000100
    }
}
