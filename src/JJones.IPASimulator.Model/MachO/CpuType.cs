namespace JJones.IPASimulator.Model.MachO
{
    public enum CpuType : int
    {
        PowerPC = 18,
        i386 = 7,
        ARM = 12,
        PowerPC64 = PowerPC | CpuMask.Abi64,
        x86_64 = i386 | CpuMask.Abi64,
        ARM64 = ARM | CpuMask.Abi64
    }
}
