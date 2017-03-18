namespace JJones.IPASimulator.Model.MachO
{
    public class Section
    {
        public const string Text = "__text";
        public const string FVMLibInit0 = "__fvmlib_init0";
        public const string FVMLibInit1 = "__fvmlib_init1";
        public const string Data = "__data";
        public const string Bss = "__bss";
        public const string Common = "__common";
        public const string ObjCSymbols = "__symbol_table";
        public const string ObjCModules = "__module_info";
        public const string ObjCStrings = "__selector_strs";
        public const string ObjCRefs = "__selector_refs";
        public const string IconHeader = "__header";
        public const string IconTiff = "__tiff";

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
