using System;

namespace JJones.IPASimulator.Model.MachO.Commands
{
    public class UuidCommand : LoadCommand
    {
        public new const uint StructureSize = 16 + LoadCommand.StructureSize;

        public UuidCommand(uint size, Guid uuid) : base(LoadCommandType.Uuid, size)
        {
            if (size != StructureSize)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

            Uuid = uuid;
        }

        public Guid Uuid { get; }
    }
}
