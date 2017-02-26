using MiscUtil.IO;

namespace JJones.IPASimulator.Model.MachO
{
    public class MachHeader
    {
        public static MachHeader TryRead(EndianBinaryReader rdr, EndianBinaryReader peekingRdr)
        {
            var magic = peekingRdr.ReadUInt32();
            MachHeaderKind kind;
            if (magic == 0xFEEDFACE)
            {
                kind = MachHeaderKind.x86;
            }
            else if (magic == 0xFEEDFACF)
            {
                kind = MachHeaderKind.x64;
            }
            else
            {
                return null;
            }
            rdr.ReadUInt32(); // magic

            var cpuType = rdr.ReadUInt32();
            var cpuSubtype = rdr.ReadUInt32();
            var filetype = rdr.ReadUInt32();
            var ncmds = rdr.ReadUInt32();
            var sizeofcmds = rdr.ReadUInt32();
            var flags = rdr.ReadUInt32();
            if (kind == MachHeaderKind.x64)
            {
                rdr.ReadUInt32(); // reserved
            }
            return new MachHeader(kind, (CpuType)cpuType, (CpuSubtype)cpuSubtype, filetype, ncmds, sizeofcmds, flags);
        }

        private MachHeader(MachHeaderKind kind, CpuType cpuType, CpuSubtype cpuSubtype, uint filetype, uint ncmds, uint sizeofcmds, uint flags)
        {
            Kind = kind;
            CpuType = cpuType;
            CpuSubtype = cpuSubtype;
            FileType = filetype;
            NCmds = ncmds;
            SizeOfCmds = sizeofcmds;
            Flags = flags;
        }
        
        public MachHeaderKind Kind { get; }
        public CpuType CpuType { get; }
        public CpuSubtype CpuSubtype { get; }
        public uint FileType { get; }
        public uint NCmds { get; }
        public uint SizeOfCmds { get; }
        public uint Flags { get; }
    }
}
