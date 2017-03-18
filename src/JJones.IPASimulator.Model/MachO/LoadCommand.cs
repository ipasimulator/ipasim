namespace JJones.IPASimulator.Model.MachO
{
    public class LoadCommand
    {
        public LoadCommand(LoadCommandType type, uint size)
        {
            Type = type;
            Size = size;
        }

        public LoadCommandType Type { get; }
        public uint Size { get; }
    }
}
