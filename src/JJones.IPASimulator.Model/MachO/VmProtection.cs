using System;

namespace JJones.IPASimulator.Model.MachO
{
    [Flags]
    public enum VmProtection : int
    {
        None,
        Read,
        Write,
        Execute = 0x4,
        Default = Read | Write,
        All = Read | Write | Execute,
        NoChange = 0x8,
        Copy = 0x10,
        WantsCopy = 0x10,
        IsMask = 0x40,
        StripRead = 0x80,
        ExecuteOnly = Execute | StripRead
    }
}
