using System;

namespace JJones.IPASimulator.Model.MachO
{
    [Flags]
    public enum SegmentFlags : uint
    {
        None,
        HighVM,
        FVMLib,
        NoReloc = 0x4,
        ProtectedVersion1 = 0x8
    }
}
