using JJones.IPASimulator.Model.Conversion;
using JJones.IPASimulator.Model.IO;
using MiscUtil.Conversion;
using MiscUtil.IO;
using System;
using System.IO;

namespace JJones.IPASimulator.Model.MachO
{
    public class MachOReader : IDisposable
    {
        private readonly GeneralEndianBitConverter bitConverter;
        private readonly EndianBinaryReader rdr, peekingRdr;

        public MachOReader(Stream stream)
        {
            var peekableStream = new PeekableStream(new CountingStream(stream), 4);
            bitConverter = new GeneralEndianBitConverter(Endianness.BigEndian);
            rdr = new EndianBinaryReader(bitConverter, peekableStream);
            peekingRdr = new EndianBinaryReader(bitConverter, new PeekingStream(peekableStream));
        }

        public uint NFatArch { get; private set; }
        public MachHeader MachHeader { get; private set; }

        public bool TryReadHeader()
        {
            return TryReadFatHeader() ||
                TryReadMachHeader();
        }
        public bool TryReadFatHeader()
        {
            if (IsMagic(0xCAFEBABE))
            {
                NFatArch = rdr.ReadUInt32();
                return true;
            }
            return false;
        }
        public bool TryReadMachHeader()
        {
            var magic = peekingRdr.ReadUInt32();
            MachHeaderKind kind;
            if (magic == 0xFEEDFACE)
            {
                kind = MachHeaderKind.x86;
            }
            else if (magic == 0xCEFAEDFE)
            {
                kind = MachHeaderKind.x86;
                bitConverter.SwitchEndianness();
            }
            else if (magic == 0xFEEDFACF)
            {
                kind = MachHeaderKind.x64;
            }
            else if (magic == 0xCFFAEDFE)
            {
                kind = MachHeaderKind.x64;
                bitConverter.SwitchEndianness();
            }
            else
            {
                return false;
            }
            rdr.ReadUInt32(); // magic

            var cpuType = rdr.ReadUInt32();
            var cpuSubtype = rdr.ReadUInt32();
            var filetype = rdr.ReadUInt32();
            var ncmds = rdr.ReadUInt32();
            var sizeofcmds = rdr.ReadUInt32();
            var flags = rdr.ReadUInt32();
            if (kind == MachHeaderKind.x64)
            {
                rdr.ReadUInt32(); // reserved
            }
            MachHeader = new MachHeader(kind, (CpuType)cpuType, cpuSubtype, filetype, ncmds, sizeofcmds, flags);
            return true;
        }
        public FatArchitecture ReadFatArch()
        {
            var cpuType = rdr.ReadUInt32();
            var cpuSubtype = rdr.ReadUInt32();
            var offset = rdr.ReadUInt32();
            var size = rdr.ReadUInt32();
            var align = rdr.ReadUInt32();
            return new FatArchitecture((CpuType)cpuType, cpuSubtype, offset, size, align);
        }
        public void SeekArch(FatArchitecture arch)
        {
            var count = arch.Offset - rdr.BaseStream.Position;
            var buffer = new byte[1024];
            var read = 0L;
            while (read < count)
            {
                var toRead = (int)Math.Min(count - read, 1024);
                var result = rdr.Read(buffer, 0, toRead);
                if (result != toRead)
                {
                    throw new EndOfStreamException();
                }
                read += result;
            }
        }
        public void Dispose()
        {
            rdr.Dispose();
            peekingRdr.Dispose();
        }

        private bool IsMagic(uint value)
        {
            var magic = peekingRdr.ReadUInt32();
            if (magic == value)
            {
                rdr.ReadUInt32(); // Skips magic.
                return true;
            }
            return false;
        }
    }
}
