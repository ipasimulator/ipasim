namespace JJones.IPASimulator.Model.MachO
{
    public enum CpuMask : int
    {
        /// <summary>
        /// Mask for architecture bits
        /// </summary>
        Architecture = unchecked((int)0xff000000),
        /// <summary>
        /// 64 bit ABI
        /// </summary>
        Abi64 = 0x01000000
    }
}
