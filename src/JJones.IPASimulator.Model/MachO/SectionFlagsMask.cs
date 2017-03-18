namespace JJones.IPASimulator.Model.MachO
{
    public enum SectionFlagsMask : uint
    {
        Type = 0x000000ff,
        Attributes = 0xffffff00,
        UserAttributes = 0xff000000,
        SystemAttributes = 0x00ffff00
    }
}
