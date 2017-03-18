namespace JJones.IPASimulator.Model.MachO
{
    public abstract class SegmentCommandBase : LoadCommand
    {
        public const string PageZero = "__PAGEZERO";
        public const string Text = "__TEXT";
        public const string Data = "__DATA";
        public const string ObjC = "__OBJC";
        public const string Icon = "__ICON";
        public const string LinkEdit = "__LINKEDIT";
        public const string UnixStack = "__UNIXSTACK";
        public const string Import = "__IMPORT";

        public SegmentCommandBase(LoadCommandType type, uint size, string segmentName, VmProtection maxProtection, VmProtection initProtection, uint nSects, SegmentFlags flags) : base(type, size)
        {
            SegmentName = segmentName;
            MaxProtection = maxProtection;
            InitProtection = initProtection;
            NSects = nSects;
            Flags = flags;
        }

        public string SegmentName { get; }
        public VmProtection MaxProtection { get; }
        public VmProtection InitProtection { get; }
        public uint NSects { get; }
        public SegmentFlags Flags { get; }
    }
}
