using System;

namespace JJones.IPASimulator.Model.MachO
{
    public class DyldInfoCommand : LoadCommand
    {
        public new const uint StructureSize = 40 + LoadCommand.StructureSize;

        public DyldInfoCommand(LoadCommandType type, uint size, uint rebaseOffset, uint rebaseSize, uint bindOffset, uint bindSize, uint weakBindOffset, uint weakBindSize, uint lazyBindOffset, uint lazyBindSize, uint exportOffset, uint exportSize) : base(type, size)
        {
            if (type != LoadCommandType.DyldInfo && type != LoadCommandType.DyldInfoOnly)
            {
                throw new ArgumentOutOfRangeException(nameof(type));
            }
            if (size != StructureSize)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

            RebaseOffset = rebaseOffset;
            RebaseSize = rebaseSize;
            BindOffset = bindOffset;
            BindSize = bindSize;
            WeakBindOffset = weakBindOffset;
            WeakBindSize = weakBindSize;
            LazyBindOffset = lazyBindOffset;
            LazyBindSize = lazyBindSize;
            ExportOffset = exportOffset;
            ExportSize = exportSize;
        }

        public uint RebaseOffset { get; }
        public uint RebaseSize { get; }
        public uint BindOffset { get; }
        public uint BindSize { get; }
        public uint WeakBindOffset { get; }
        public uint WeakBindSize { get; }
        public uint LazyBindOffset { get; }
        public uint LazyBindSize { get; }
        public uint ExportOffset { get; }
        public uint ExportSize { get; }
    }
}
