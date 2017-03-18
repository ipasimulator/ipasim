namespace JJones.IPASimulator.Model.MachO
{
    public enum SectionType : uint
    {
        Regular,
        ZeroFill,
        CStringLiterals,
        FourByteLiterals,
        EightByteLiterals,
        LiteralPointers,
        NonlazySymbolPointers,
        LazySymbolPointers,
        SymbolStubs,
        ModInitFuncPointers,
        ModTermFuncPointers,
        Coalesced,
        GBZeroFill,
        Interposing,
        SizteenByteLiterals,
        DTraceDOF,
        LazyDylibSymbolPointers,
        ThreadLocalRegular,
        ThreadLocalZeroFill,
        ThreadLocalVariables,
        ThreadLocalVariablePointers,
        ThreadLocalInitFunctionPointers
    }
}
