using System;
using System.IO;

namespace JJones.IPASimulator.Model.IO
{
    public class CountingStream : Stream
    {
        private readonly Stream str;
        private long position;

        public CountingStream(Stream stream)
        {
            str = stream;
        }

        public override bool CanRead => str.CanRead;
        public override bool CanSeek => str.CanSeek;
        public override bool CanWrite => str.CanWrite;
        public override long Length => str.Length;
        public override long Position
        {
            get { return position; }
            set
            {
                str.Position = value;
                position = value;
            }
        }

        public override void Flush() => str.Flush();
        public override int Read(byte[] buffer, int offset, int count)
        {
            var result = str.Read(buffer, offset, count);
            if (result > 0)
            {
                position += result;
            }
            return result;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            var result = str.Seek(offset, origin);
            switch (origin)
            {
                case SeekOrigin.Begin:
                    position = result;
                    break;
                case SeekOrigin.Current:
                    position += result;
                    break;
                case SeekOrigin.End:
                    position = Length + result;
                    break;
            }
            return result;
        }
        public override void SetLength(long value)
        {
            str.SetLength(value);
            position = Math.Min(value, position);
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            str.Write(buffer, offset, count);
            position += count;
        }
    }
}
