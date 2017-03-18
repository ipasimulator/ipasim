namespace JJones.IPASimulator.Model.MachO
{
    public class SegmentCommand : LoadCommand
    {
        public SegmentCommand(uint size, string segmentName, uint vmAddress, uint vmSize, uint fileOffset, uint fileSize, VmProtection maxProtection, VmProtection initProtection, uint nSects, SegmentFlags flags) : base(LoadCommandType.Segment, size)
        {
            SegmentName = segmentName;
            VMAddress = vmAddress;
            VMSize = vmSize;
            FileOffset = fileOffset;
            FileSize = fileSize;
            MaxProtection = maxProtection;
            InitProtection = initProtection;
            NSects = nSects;
            Flags = flags;
        }

        public string SegmentName { get; }
        public uint VMAddress { get; }
        public uint VMSize { get; }
        public uint FileOffset { get; }
        public uint FileSize { get; }
        public VmProtection MaxProtection { get; }
        public VmProtection InitProtection { get; }
        public uint NSects { get; }
        public SegmentFlags Flags { get; }
    }
}
