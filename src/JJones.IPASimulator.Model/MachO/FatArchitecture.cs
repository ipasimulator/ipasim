using MiscUtil.IO;

namespace JJones.IPASimulator.Model.MachO
{
    public class FatArchitecture
    {
        public static FatArchitecture Read(EndianBinaryReader rdr)
        {
            var cpuType = rdr.ReadUInt32();
            var cpuSubtype = rdr.ReadUInt32();
            var offset = rdr.ReadUInt32();
            var size = rdr.ReadUInt32();
            var align = rdr.ReadUInt32();
            return new FatArchitecture((CpuType)cpuType, (CpuSubtype)cpuSubtype, offset, size, align);
        }

        private FatArchitecture(CpuType cpuType, CpuSubtype cpuSubtype, uint offset, uint size, uint align)
        {
            CpuType = cpuType;
            CpuSubtype = cpuSubtype;
            Offset = offset;
            Size = size;
            Align = align;
        }

        public CpuType CpuType { get; }
        public CpuSubtype CpuSubtype { get; }
        public uint Offset { get; }
        public uint Size { get; }
        public uint Align { get; }
    }
}
