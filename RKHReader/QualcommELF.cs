// Copyright (c) 2018, Rene Lergner - @Heathcliff74xda
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using ELFSharp.ELF;
using System;
using System.IO;
using System.Security.Cryptography;

namespace RKHReader
{
    internal class QualcommELF
    {
        internal byte[] Binary;
        internal uint HeaderOffset;
        internal QualcommPartitionHeaderType HeaderType;
        internal uint ImageOffset;
        internal uint ImageAddress;
        internal uint ImageSize;
        internal uint CodeSize;
        internal uint SignatureAddress;
        internal uint SignatureSize;
        internal uint SignatureOffset;
        internal uint CertificatesAddress;
        internal uint CertificatesSize;
        internal uint CertificatesOffset;
        internal byte[] RootKeyHash = null;

        internal QualcommELF(string Path) : this(File.ReadAllBytes(Path)) { }

        internal QualcommELF(byte[] ELFBinary, uint Offset = 0)
        {
#if DEBUG
            System.Diagnostics.Debug.Print("Loader: " + Converter.ConvertHexToString(new SHA256Managed().ComputeHash(ELFBinary, 0, ELFBinary.Length), ""));
#endif

            IELF image = ELFReader.Load(new MemoryStream(ELFBinary), true);

            foreach (ELFSharp.ELF.Segments.ISegment? segment in image.Segments)
            {
                if (((int)segment.Flags & 0x0F000000) == 0x02000000 && segment.Type == ELFSharp.ELF.Segments.SegmentType.Null)
                {
                    if (Binary != null)
                    {
                        throw new Exception("ELF File seems to have more than one signing segment!");
                    }

                    Binary = segment.GetMemoryContents();
                }
            }

            if (Binary == null)
            {
                throw new Exception("Unable to parse ELF File!");
            }

            byte[] LongHeaderPattern = new byte[] { 0xD1, 0xDC, 0x4B, 0x84, 0x34, 0x10, 0xD7, 0x73, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            byte[] LongHeaderMask = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            
            if (ByteOperations.FindPattern(Binary, Offset, (uint)LongHeaderPattern.Length, LongHeaderPattern, LongHeaderMask, null) == null)
            {
                HeaderType = QualcommPartitionHeaderType.Short;
                ImageOffset = Offset;
                HeaderOffset = ImageOffset + 8;
            }
            else
            {
                HeaderType = QualcommPartitionHeaderType.Long;
                ImageOffset = Offset;
                HeaderOffset = ImageOffset + (uint)LongHeaderPattern.Length;
            }

            uint Version = ByteOperations.ReadUInt32(Binary, ImageOffset + 0X04);

            if (ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X00) != 0)
            {
                ImageOffset = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X00);
            }
            else if (HeaderType == QualcommPartitionHeaderType.Short)
            {
                ImageOffset += 0x28;
            }
            else
            {
                ImageOffset += 0x50;
            }

            ImageAddress = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X04);
            ImageSize = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X08);
            CodeSize = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X0C);
            SignatureAddress = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X10);
            SignatureSize = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X14);
            CertificatesAddress = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X18);
            CertificatesSize = ByteOperations.ReadUInt32(Binary, HeaderOffset + 0X1C);

            if (SignatureAddress == 0xFFFFFFFF)
            {
                SignatureAddress = ImageAddress + CodeSize;
            }

            if (CertificatesAddress == 0xFFFFFFFF)
            {
                CertificatesAddress = SignatureAddress + SignatureSize;
            }

            // Headers newer than version 5 need more padding here
            if (Version > 5)
            {
                ImageOffset += 0x80;
            }

            SignatureOffset = ImageOffset + CodeSize;
            CertificatesOffset = ImageOffset + CodeSize + SignatureSize + 0xF0;

            // Keeping just in case
            // SignatureOffset = SignatureAddress - ImageAddress + ImageOffset;
            // CertificatesOffset = ImageSize - CertificatesSize + ImageOffset;

            uint CurrentCertificateOffset = CertificatesOffset;
            uint CertificateSize = 0;

            Console.WriteLine($"CertificatesOffset: 0x{CertificatesOffset:X}");
            Console.WriteLine($"CertificatesSize: 0x{CertificatesSize:X}");

            while (CurrentCertificateOffset < (CertificatesOffset + CertificatesSize))
            {
                if ((Binary[CurrentCertificateOffset] == 0x30) && (Binary[CurrentCertificateOffset + 1] == 0x82))
                {
                    CertificateSize = (uint)(Binary[CurrentCertificateOffset + 2] * 0x100) + Binary[CurrentCertificateOffset + 3] + 4; // Big endian!

                    if ((CurrentCertificateOffset + CertificateSize) == (CertificatesOffset + CertificatesSize))
                    {
                        // This is the last certificate. So this is the root key.
                        RootKeyHash = new SHA256Managed().ComputeHash(Binary, (int)CurrentCertificateOffset, (int)CertificateSize);

#if DEBUG
                        System.Diagnostics.Debug.Print("RKH: " + Converter.ConvertHexToString(RootKeyHash, ""));
#endif
                    }
#if DEBUG
                    else
                    {
                        System.Diagnostics.Debug.Print("Cert: " + Converter.ConvertHexToString(new SHA256Managed().ComputeHash(Binary, (int)CurrentCertificateOffset, (int)CertificateSize), ""));
                    }
#endif
                    CurrentCertificateOffset += CertificateSize;
                }
                else
                {
                    if ((RootKeyHash == null) && (CurrentCertificateOffset > CertificatesOffset))
                    {
                        CurrentCertificateOffset -= CertificateSize;

                        // This is the last certificate. So this is the root key.
                        RootKeyHash = new SHA256Managed().ComputeHash(Binary, (int)CurrentCertificateOffset, (int)CertificateSize);

#if DEBUG
                        System.Diagnostics.Debug.Print("RKH: " + Converter.ConvertHexToString(RootKeyHash, ""));
#endif
                    }
                    break;
                }
            }
        }
    }
}
