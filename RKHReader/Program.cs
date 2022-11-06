namespace RKHReader
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1 || !File.Exists(args[0]))
            {
                Console.WriteLine("Usage: <Path to Qualcomm Signed file>");
            }

            PrintRKHFromFile(args[0]);
        }

        static void PrintRKHFromFile(string file)
        {
            QualcommPartition qualcommPartition = new(file);
            if (qualcommPartition.RootKeyHash != null)
            {
                Console.WriteLine(file);
                Console.WriteLine("RKH: " + Converter.ConvertHexToString(qualcommPartition.RootKeyHash, ""));
            }
        }
    }
}