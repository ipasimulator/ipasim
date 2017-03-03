namespace JJones.IPASimulator.Model.MachO
{
    public enum CpuMask : int
    {
        /// <summary>
        /// Mask for architecture bits
        /// </summary>
        CPU_ARCH_MASK = unchecked((int)0xff000000),
        /// <summary>
        /// 64 bit ABI
        /// </summary>
        CPU_ARCH_ABI64 = 0x01000000
    }
}
