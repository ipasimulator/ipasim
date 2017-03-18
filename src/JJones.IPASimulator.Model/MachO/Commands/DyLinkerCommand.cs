namespace JJones.IPASimulator.Model.MachO.Commands
{
    public class DyLinkerCommand : LoadCommand
    {
        public DyLinkerCommand(uint size, string name) : base(LoadCommandType.LoadDyLinker, size)
        {
            Name = name;
        }

        public string Name { get; }
    }
}
