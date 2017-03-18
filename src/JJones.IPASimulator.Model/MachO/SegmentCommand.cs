namespace JJones.IPASimulator.Model.MachO
{
    public class SegmentCommand : SegmentCommandBase
    {
        public SegmentCommand(uint size, string segmentName, uint vmAddress, uint vmSize, uint fileOffset, uint fileSize, VmProtection maxProtection, VmProtection initProtection, uint nSects, SegmentFlags flags)
            : base(LoadCommandType.Segment, size, segmentName, maxProtection, initProtection, nSects, flags)
        {
            VMAddress = vmAddress;
            VMSize = vmSize;
            FileOffset = fileOffset;
            FileSize = fileSize;
        }

        public uint VMAddress { get; }
        public uint VMSize { get; }
        public uint FileOffset { get; }
        public uint FileSize { get; }
    }
}
