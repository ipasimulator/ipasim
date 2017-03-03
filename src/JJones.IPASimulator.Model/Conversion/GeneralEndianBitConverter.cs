using MiscUtil.Conversion;
using System;

namespace JJones.IPASimulator.Model.Conversion
{
    public class GeneralEndianBitConverter : EndianBitConverter
    {
        private Endianness _endianness;

        public GeneralEndianBitConverter(Endianness endianness)
        {
            _endianness = endianness;
        }

        public override Endianness Endianness
        {
            get { return _endianness; }
        }

        private EndianBitConverter GetConverter()
        {
            if (IsLittleEndian())
            {
                return Little;
            }
            return Big;
        }

        public override bool IsLittleEndian() => Endianness == Endianness.LittleEndian;
        public void SetEndianness(Endianness value)
        {
            _endianness = value;
        }
        public void SwitchEndianness()
        {
            SetEndianness(Endianness == Endianness.BigEndian ? Endianness.LittleEndian : Endianness.BigEndian);
        }
        protected override void CopyBytesImpl(long value, int bytes, byte[] buffer, int index)
        {
            var conv = GetConverter();
            switch (bytes)
            {
                case 1:
                    conv.CopyBytes(unchecked((byte)value), buffer, index);
                    break;
                case 2:
                    conv.CopyBytes(unchecked((ushort)value), buffer, index);
                    break;
                case 4:
                    conv.CopyBytes(unchecked((uint)value), buffer, index);
                    break;
                case 8:
                    conv.CopyBytes(value, buffer, index);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(bytes));
            }
        }
        protected override long FromBytes(byte[] value, int startIndex, int bytesToConvert)
        {
            var conv = GetConverter();
            switch (bytesToConvert)
            {
                case 2:
                    return conv.ToUInt16(value, startIndex);
                case 4:
                    return conv.ToUInt32(value, startIndex);
                case 8:
                    return conv.ToInt64(value, startIndex);
                default:
                    throw new ArgumentOutOfRangeException(nameof(bytesToConvert));
            }
        }
    }
}
