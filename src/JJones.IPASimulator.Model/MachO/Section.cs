namespace JJones.IPASimulator.Model.MachO
{
    public class Section
    {
        public Section(string sectionName, string segmentName, uint address, uint size, uint offset, uint align, uint relOffset, uint nReloc, uint flags, uint reserved1, uint reserved2)
            : this(sectionName, segmentName, address, size, offset, align, relOffset, nReloc,
                  (SectionType)(flags & (uint)SectionFlagsMask.Type),
                  (SectionAttributes)(flags & (uint)SectionFlagsMask.Attributes),
                  reserved1, reserved2)
        {
        }
        public Section(string sectionName, string segmentName, uint address, uint size, uint offset, uint align, uint relOffset, uint nReloc, SectionType type, SectionAttributes attributes, uint reserved1, uint reserved2)
        {
            SectionName = sectionName;
            SegmentName = segmentName;
            Address = address;
            Size = size;
            Offset = offset;
            Align = align;
            RelOffset = relOffset;
            NReloc = nReloc;
            Type = type;
            Attributes = attributes;
            Reserved1 = reserved1;
            Reserved2 = reserved2;
        }

        public string SectionName { get; }
        public string SegmentName { get; }
        public uint Address { get; }
        public uint Size { get; }
        public uint Offset { get; }
        public uint Align { get; }
        public uint RelOffset { get; }
        public uint NReloc { get; }
        public SectionType Type { get; }
        public SectionAttributes Attributes { get; }
        public uint Reserved1 { get; }
        public uint Reserved2 { get; }
    }
}
