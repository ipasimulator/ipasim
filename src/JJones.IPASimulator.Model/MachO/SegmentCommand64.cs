namespace JJones.IPASimulator.Model.MachO
{
    public class SegmentCommand64 : SegmentCommandBase
    {
        public SegmentCommand64(uint size, string segmentName, ulong vmAddress, ulong vmSize, ulong fileOffset, ulong fileSize, VmProtection maxProtection, VmProtection initProtection, uint nSects, SegmentFlags flags)
             : base(LoadCommandType.Segment, size, segmentName, maxProtection, initProtection, nSects, flags)
        {
            VMAddress = vmAddress;
            VMSize = vmSize;
            FileOffset = fileOffset;
            FileSize = fileSize;
        }

        public ulong VMAddress { get; }
        public ulong VMSize { get; }
        public ulong FileOffset { get; }
        public ulong FileSize { get; }
    }
}
