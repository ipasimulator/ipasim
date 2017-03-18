using System;

namespace JJones.IPASimulator.Model.MachO.Commands
{
    public class DySymtabCommand : LoadCommand
    {
        public new const uint StructureSize = 72 + LoadCommand.StructureSize;

        public DySymtabCommand(uint size, uint localSym, uint nLocalSym, uint extDefSym, uint nExtDefSym, uint undefSym, uint nUndefSym, uint tocOffset, uint nToc, uint modTabOffset, uint nModTab, uint extRefSymOffset, uint nExtRefSyms, uint indirectSymOffset, uint nIndirectSyms, uint extRelOffset, uint nExtRel, uint locRelOffset, uint nLocRel) : base(LoadCommandType.DySymtab, size)
        {
            if (size != StructureSize)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

            ILocalSym = localSym;
            NLocalSym = nLocalSym;
            IExtDefSym = extDefSym;
            NExtDefSym = nExtDefSym;
            IUndefSym = undefSym;
            NUndefSym = nUndefSym;
            TocOffset = tocOffset;
            NToc = nToc;
            ModTabOffset = modTabOffset;
            NModTab = nModTab;
            ExtRefSymOffset = extRefSymOffset;
            NExtRefSyms = nExtRefSyms;
            IndirectSymOffset = indirectSymOffset;
            NIndirectSyms = nIndirectSyms;
            ExtRelOffset = extRelOffset;
            NExtRel = nExtRel;
            LocRelOffset = locRelOffset;
            NLocRel = nLocRel;
        }

        public uint ILocalSym { get; }
        public uint NLocalSym { get; }
        public uint IExtDefSym { get; }
        public uint NExtDefSym { get; }
        public uint IUndefSym { get; }
        public uint NUndefSym { get; }
        public uint TocOffset { get; }
        public uint NToc { get; }
        public uint ModTabOffset { get; }
        public uint NModTab { get; }
        public uint ExtRefSymOffset { get; }
        public uint NExtRefSyms { get; }
        public uint IndirectSymOffset { get; }
        public uint NIndirectSyms { get; }
        public uint ExtRelOffset { get; }
        public uint NExtRel { get; }
        public uint LocRelOffset { get; }
        public uint NLocRel { get; }
    }
}
