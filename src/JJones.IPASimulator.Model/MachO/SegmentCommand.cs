using System;

namespace JJones.IPASimulator.Model.MachO
{
    public class SegmentCommand : SegmentCommandBase
    {
        public new const uint StructureSize = 16 + SegmentCommandBase.StructureSize;

        public SegmentCommand(uint size, string segmentName, uint vmAddress, uint vmSize, uint fileOffset, uint fileSize, VmProtection maxProtection, VmProtection initProtection, uint nSects, SegmentFlags flags)
            : base(LoadCommandType.Segment, size, segmentName, maxProtection, initProtection, nSects, flags)
        {
            if (size != StructureSize + nSects * Section.StructureSize)
            {
                throw new ArgumentOutOfRangeException(nameof(size));
            }

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
