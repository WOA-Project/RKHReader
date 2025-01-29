using System.Diagnostics;
using System.Security.Cryptography;

namespace RKHReader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1 || !(File.Exists(args[0]) || Directory.Exists(args[0])))
            {
                Console.WriteLine("Usage: <Path to Qualcomm Signed file>");
            }

            if (File.Exists(args[0]))
            {
                PrintRKHFromFile3(args[0]);
            }

            if (Directory.Exists(args[0]))
            {
                foreach (var el in Directory.EnumerateFiles(args[0], "*.*", SearchOption.AllDirectories))
                {
                    PrintRKHFromFile3(el);
                }
            }
        }

        public static byte[] PrintDERLocations(string file)
        {
            using Stream fileStream = File.OpenRead(file);
            using BinaryReader reader = new(fileStream);

            List<byte[]> Signatures = new();
            uint LastOffset = 0;

            for (uint i = 0; i < fileStream.Length - 6; i++)
            {
                fileStream.Seek(i, SeekOrigin.Begin);

                ushort offset0 = reader.ReadUInt16();
                short offset1 = (short)((reader.ReadByte() << 8) | reader.ReadByte());
                ushort offset2 = reader.ReadUInt16();

                if (offset0 == 0x8230 && offset1 >= 0 && offset2 == 0x8230)
                {
                    int CertificateSize = offset1 + 4; // Header Size is 4

                    bool IsCertificatePartOfExistingChain = LastOffset == 0 || LastOffset == i;
                    if (!IsCertificatePartOfExistingChain)
                    {
                        Debug.WriteLine("Chain broke right here: " + Signatures.Count);
                        //break;
                    }

                    LastOffset = i + (uint)CertificateSize;

                    fileStream.Seek(i, SeekOrigin.Begin);
                    Signatures.Add(reader.ReadBytes(CertificateSize));
                }
            }

            byte[] RootCertificate = Signatures[^1];

            byte[] RKH = null;

            for (int i = 0; i < Signatures.Count; i++)
            {
                byte[] Hash = new SHA384Managed().ComputeHash(Signatures[i]);

                // The last certificate in the chain is the Root Key Hash.
                if (i + 1 == Signatures.Count)
                {
                    Debug.WriteLine("RKH: " + Converter.ConvertHexToString(Hash, ""));
                    //File.WriteAllBytes(i + ".cer", Signatures[i]);
                    RKH = Hash;
                }
                else
                {
#if DEBUG
                    Debug.WriteLine("Cert: " + Converter.ConvertHexToString(Hash, ""));
                    //File.WriteAllBytes(i + ".cer", Signatures[i]);
#endif
                }
            }

            return RKH;
        }

        static void PrintRKHFromFile(string file)
        {
            try
            {
                QualcommPartition qualcommPartition = new(file);
                if (qualcommPartition.RootKeyHash != null)
                {
                    Console.WriteLine(file);
                    Console.WriteLine("RKH: " + Converter.ConvertHexToString(qualcommPartition.RootKeyHash, ""));
                    Console.Error.WriteLine(Converter.ConvertHexToString(qualcommPartition.RootKeyHash, ""));
                }
                else
                {
                    Console.WriteLine(file);
                    Console.WriteLine("FAIL!");
                }
            } catch (Exception e)
            {
                Console.WriteLine(file);
                Console.WriteLine("EXCEPTION!");
                //Console.WriteLine(e);
            }
        }

        static void PrintRKHFromFile2(string file)
        {
            try
            {
                QualcommELF qualcommPartition = new(file);
                if (qualcommPartition.RootKeyHash != null)
                {
                    Console.WriteLine(file);
                    Console.WriteLine("RKH: " + Converter.ConvertHexToString(qualcommPartition.RootKeyHash, ""));
                    Console.Error.WriteLine(Converter.ConvertHexToString(qualcommPartition.RootKeyHash, ""));
                }
                else
                {
                    Console.WriteLine(file);
                    Console.WriteLine("FAIL!");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(file);
                Console.WriteLine("EXCEPTION!");
                //Console.WriteLine(e);
            }
        }

        static void PrintRKHFromFile3(string file)
        {
            try
            {
                byte[] RootKeyHash = PrintDERLocations(file);;
                if (RootKeyHash != null)
                {
                    Console.WriteLine(file);
                    Console.WriteLine("RKH: " + Converter.ConvertHexToString(RootKeyHash, ""));
                    Console.Error.WriteLine(Converter.ConvertHexToString(RootKeyHash, ""));
                }
                else
                {
                    Console.WriteLine(file);
                    Console.WriteLine("FAIL!");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(file);
                Console.WriteLine("EXCEPTION!");
                //Console.WriteLine(e);
            }
        }
    }
}