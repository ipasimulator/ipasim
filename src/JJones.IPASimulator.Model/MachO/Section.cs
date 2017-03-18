namespace JJones.IPASimulator.Model.MachO
{
    public class Section : SectionBase
    {
        public Section(string sectionName, string segmentName, uint address, uint size, uint offset, uint align, uint relOffset, uint nReloc, uint flags, uint reserved1, uint reserved2)
            : base(sectionName, segmentName, offset, align, relOffset, nReloc, flags, reserved1, reserved2)
        {
            Address = address;
            Size = size;
        }
        public Section(string sectionName, string segmentName, uint address, uint size, uint offset, uint align, uint relOffset, uint nReloc, SectionType type, SectionAttributes attributes, uint reserved1, uint reserved2)
            : base(sectionName, segmentName, offset, align, relOffset, nReloc, type, attributes, reserved1, reserved2)
        {
            Address = address;
            Size = size;
        }

        public uint Address { get; }
        public uint Size { get; }
    }
}
