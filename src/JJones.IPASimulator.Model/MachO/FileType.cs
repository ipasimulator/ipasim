namespace JJones.IPASimulator.Model.MachO
{
    public enum FileType : uint
    {
        Object = 1,
        Executable,
        FixedVM,
        Core,
        Preload,
        Dylib,
        DyLinker,
        Bundle,
        DylibStub,
        Dsym,
        KextBundle
    }
}
