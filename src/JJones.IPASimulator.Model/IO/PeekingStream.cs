using System;
using System.IO;

namespace JJones.IPASimulator.Model.IO
{
    /// <summary>
    /// A <see cref="Stream"/> wrapper which uses <see cref="PeekableStream.Peek(byte[], int, int)"/> method whenever <see cref="Stream.Read(byte[], int, int)"/> method is called.
    /// </summary>
    public class PeekingStream : Stream
    {
        private readonly PeekableStream str;

        public PeekingStream(PeekableStream stream)
        {
            str = stream;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => str.Length;
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                str.Dispose();
            }

            base.Dispose(disposing);
        }
        public override void Flush()
        {
            throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            return str.Peek(buffer, offset, count);
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
