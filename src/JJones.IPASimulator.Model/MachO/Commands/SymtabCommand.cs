using System;

namespace JJones.IPASimulator.Model.MachO.Commands
{
    public class SymtabCommand : LoadCommand
    {
        public new const uint StructureSize = 16 + LoadCommand.StructureSize;

        public SymtabCommand(uint size, uint symOffset, uint nSyms, uint strOffset, uint strSize) : base(LoadCommandType.Symtab, size)
        {
            if (size != StructureSize)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

            SymOffset = symOffset;
            NSyms = nSyms;
            StrOffset = strOffset;
            StrSize = strSize;
        }

        public uint SymOffset { get; }
        public uint NSyms { get; }
        public uint StrOffset { get; }
        public uint StrSize { get; }
    }
}
