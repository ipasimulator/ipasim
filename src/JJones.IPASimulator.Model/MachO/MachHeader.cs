using MiscUtil.IO;

namespace JJones.IPASimulator.Model.MachO
{
    public class MachHeader
    {
        public MachHeader(MachHeaderKind kind, CpuType cpuType, uint cpuSubtype, uint filetype, uint ncmds, uint sizeofcmds, uint flags)
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
        public uint CpuSubtype { get; }
        public uint FileType { get; }
        public uint NCmds { get; }
        public uint SizeOfCmds { get; }
        public uint Flags { get; }
    }
}
