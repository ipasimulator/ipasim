using JJones.IPASimulator.Model.IO;
using MiscUtil.Conversion;
using MiscUtil.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JJones.IPASimulator.Model.MachO
{
    public class MachOReader : IDisposable
    {
        private readonly EndianBinaryReader rdr, peekingRdr;

        public MachOReader(Stream stream)
        {
            rdr = new EndianBinaryReader(EndianBitConverter.Big, stream);
            peekingRdr = new EndianBinaryReader(EndianBitConverter.Big, new PeekingStream(new PeekableStream(stream, 4)));
        }

        public IReadOnlyList<FatArchitecture> FatArchitectures { get; private set; }
        public MachHeader MachHeader { get; private set; }
        
        public bool TryReadFatHeaders()
        {
            if (IsMagic(0xCAFEBABE))
            {
                var nfat_arch = rdr.ReadUInt32();
                var archs = new FatArchitecture[nfat_arch];
                for (var i = 0u; i < nfat_arch; i++) // TODO: maybe don't read them all at once.
                {
                    archs[i] = FatArchitecture.Read(rdr);
                }
                FatArchitectures = archs;
                return true;
            }
            return false;
        }
        public bool TryReadMachHeaders(FatArchitecture architecture = null)
        {
            if (architecture != null)
            {
                // Skips to architecture's offset:
                var count = architecture.Offset - rdr.BaseStream.Position;
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

            var header = MachHeader.TryRead(rdr, peekingRdr);
            MachHeader = header;
            return header != null;
        }
        public void Dispose()
        {
            rdr.Dispose();
            peekingRdr.Dispose();
        }

        private bool IsMagic(uint value)
        {
            var magic = peekingRdr.ReadUInt32();
            if (magic == 0xFEEDFACE)
            {
                rdr.ReadUInt32(); // Skips magic.
                return true;
            }
            return false;
        }
    }
}
