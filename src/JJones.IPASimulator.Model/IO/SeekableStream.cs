using System;
using System.IO;

namespace JJones.IPASimulator.Model.IO
{
    public class SeekableStream : Stream
    {
        private readonly Stream stream;

        public SeekableStream(Stream stream)
        {
            this.stream = stream;
        }

        public override bool CanRead => stream.CanRead;
        public override bool CanSeek => CanRead;
        public override bool CanWrite => stream.CanWrite;
        public override long Length => stream.Length;
        public override long Position { get => stream.Position; set => stream.Position = value; }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                stream.Dispose();
            }

            base.Dispose(disposing);
        }
        public override void Flush() => stream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => stream.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (origin != SeekOrigin.Current)
            {
                throw new ArgumentOutOfRangeException(nameof(origin));
            }
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(offset));
            }

            var oldPosition = Position;

            const int bufferSize = 1024;
            var buffer = new byte[Math.Min(offset, bufferSize)];
            var i = 0;
            while (i < offset)
            {
                var count = (int)Math.Min(buffer.Length, offset - i);
                var realCount = Read(buffer, 0, count);
                if (realCount != count)
                {
                    throw new IOException();
                }
                i += realCount;
            }

            return oldPosition + offset;
        }
        public override void SetLength(long value) => stream.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => stream.Write(buffer, offset, count);
    }
}
