namespace JJones.IPASimulator.Model.MachO
{
    public class Section64 : SectionBase
    {
        public new const uint StructureSize = 16 + SectionBase.StructureSize;

        public Section64(string sectionName, string segmentName, ulong address, ulong size, uint offset, uint align, uint relOffset, uint nReloc, uint flags, uint reserved1, uint reserved2)
            : base(sectionName, segmentName, offset, align, relOffset, nReloc, flags, reserved1, reserved2)
        {
            Address = address;
            Size = size;
        }
        public Section64(string sectionName, string segmentName, ulong address, ulong size, uint offset, uint align, uint relOffset, uint nReloc, SectionType type, SectionAttributes attributes, uint reserved1, uint reserved2)
            : base(sectionName, segmentName, offset, align, relOffset, nReloc, type, attributes, reserved1, reserved2)
        {
            Address = address;
            Size = size;
        }

        public ulong Address { get; }
        public ulong Size { get; }
    }
}
