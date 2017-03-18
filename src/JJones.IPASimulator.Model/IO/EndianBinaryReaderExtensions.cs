using MiscUtil.IO;
using System;
using System.IO;

namespace JJones.IPASimulator.Model.IO
{
    public static class EndianBinaryReaderExtensions
    {
        public static char[] ReadChars(this EndianBinaryReader rdr, int count)
        {
            var data = new char[count];
            var realCount = rdr.Read(data, 0, count);
            Array.Resize(ref data, realCount);
            return data;
        }
        public static char[] ReadCharsOrThrow(this EndianBinaryReader rdr, int count)
        {
            var data = new char[count];
            var realCount = rdr.Read(data, 0, count);
            if (realCount != count)
            {
                throw new IOException();
            }
            return data;
        }
        public static string ReadNullPaddedString(this EndianBinaryReader rdr, int count)
        {
            var chars = rdr.ReadCharsOrThrow(count);
            var idx = Array.IndexOf(chars, '\0');
            if (idx < 0)
            {
                idx = chars.Length;
            }
            return new string(chars, 0, idx);
        }
    }
}
