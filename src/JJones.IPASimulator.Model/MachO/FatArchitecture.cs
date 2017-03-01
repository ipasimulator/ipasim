namespace JJones.IPASimulator.Model.MachO
{
    public class FatArchitecture
    {
        public FatArchitecture(CpuType cpuType, uint cpuSubtype, uint offset, uint size, uint align)
        {
            CpuType = cpuType;
            CpuSubtype = cpuSubtype;
            Offset = offset;
            Size = size;
            Align = align;
        }

        public CpuType CpuType { get; }
        public uint CpuSubtype { get; }
        public uint Offset { get; }
        public uint Size { get; }
        public uint Align { get; }
    }
}
