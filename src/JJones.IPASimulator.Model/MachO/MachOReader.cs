using JJones.IPASimulator.Model.Conversion;
using JJones.IPASimulator.Model.IO;
using JJones.IPASimulator.Model.MachO.Commands;
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
            var peekableStream = new PeekableStream(stream, 4);
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

            MachHeader = new MachHeader
            (
                kind,
                (CpuType)rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                (FileType)rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                (Flags)rdr.ReadUInt32()
            );
            if (kind == MachHeaderKind.x64)
            {
                rdr.ReadUInt32(); // reserved
            }
            return true;
        }
        public FatArchitecture ReadFatArch()
        {
            return new FatArchitecture
            (
                (CpuType)rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
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
        public LoadCommand ReadLoadCommand()
        {
            return new LoadCommand
            (
                (LoadCommandType)rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
        }
        public void SkipCommand(LoadCommand header)
        {
            rdr.Seek((int)(header.Size - LoadCommand.StructureSize), SeekOrigin.Current);
        }
        public SegmentCommand ReadSegmentCommand(LoadCommand header)
        {
            if (header.Type != LoadCommandType.Segment)
            {
                throw new ArgumentException(null, nameof(header));
            }

            return new SegmentCommand
            (
                header.Size,
                rdr.ReadNullPaddedString(16),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                (VmProtection)rdr.ReadInt32(),
                (VmProtection)rdr.ReadInt32(),
                rdr.ReadUInt32(),
                (SegmentFlags)rdr.ReadUInt32()
            );
        }
        public SegmentCommand64 ReadSegmentCommand64(LoadCommand header)
        {
            if (header.Type != LoadCommandType.Segment64)
            {
                throw new ArgumentException(null, nameof(header));
            }

            return new SegmentCommand64
            (
                header.Size,
                rdr.ReadNullPaddedString(16),
                rdr.ReadUInt64(),
                rdr.ReadUInt64(),
                rdr.ReadUInt64(),
                rdr.ReadUInt64(),
                (VmProtection)rdr.ReadInt32(),
                (VmProtection)rdr.ReadInt32(),
                rdr.ReadUInt32(),
                (SegmentFlags)rdr.ReadUInt32()
            );
        }
        public Section ReadSection()
        {
            return new Section
            (
                rdr.ReadNullPaddedString(16),
                rdr.ReadNullPaddedString(16),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
        }
        public DyldInfoCommand ReadDyldInfoComand(LoadCommand header)
        {
            return new DyldInfoCommand
            (
                header.Type,
                header.Size,
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
        }
        public SymtabCommand ReadSymtabCommand(LoadCommand header)
        {
            if (header.Type != LoadCommandType.Symtab)
            {
                throw new ArgumentException(null, nameof(header));
            }

            return new SymtabCommand
            (
                header.Size,
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
        }
        public DySymtabCommand ReadDySymtabCommand(LoadCommand header)
        {
            if (header.Type != LoadCommandType.DySymtab)
            {
                throw new ArgumentException(null, nameof(header));
            }

            return new DySymtabCommand
            (
                header.Size,
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32(),
                rdr.ReadUInt32()
            );
        }
        public DyLinkerCommand ReadDyLinkerCommand(LoadCommand header)
        {
            if (header.Type != LoadCommandType.LoadDyLinker)
            {
                throw new ArgumentException(null, nameof(header));
            }

            var offset = rdr.ReadUInt32();
            if (offset != LoadCommand.StructureSize + 4)
            {
                throw new IOException();
            }

            return new DyLinkerCommand
            (
                header.Size,
                rdr.ReadNullPaddedString((int)(header.Size - offset))
            );
        }
        public UuidCommand ReadUuidCommand(LoadCommand header)
        {
            if (header.Type != LoadCommandType.Uuid)
            {
                throw new ArgumentException(null, nameof(header));
            }

            return new UuidCommand
            (
                header.Size,
                new Guid(rdr.ReadBytesOrThrow(16))
            );
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
