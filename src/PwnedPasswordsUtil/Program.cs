using System;
using System.Buffers.Text;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HashSplitter
{
    class Program
    {
        private static SHA1 s_hasher = SHA1.Create();
        static void Main(string[] args)
        {
            if(args.Length != 3 || (args[1] != "-optimize" && args[1] != "-check"))
            {
                PrintHelp();
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Input file does not exist.");
            }

                using (var fileStream = File.OpenRead(args[0]))
                {
                    switch (args[1])
                    {
                        case "-optimize":
                            ConvertToBinary(fileStream, args[2]);
                            break;
                        case "-check":
                            var timer = Stopwatch.StartNew();
                            Console.WriteLine($"Password exists = {Lookup(fileStream, args[2])}, elapsed ticks = {timer.ElapsedTicks}");
                            break;
                        default:
                            throw new ArgumentException("Invalid action specified.", nameof(args));
                    }
                }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Missing arguments.");
            Console.WriteLine("INPUT_FILE -optimize OUTPUT_FILE: Creates a binary version of the hash file with no index and no counters.");
            Console.WriteLine("INPUT_FILE -check SOME_STRING: Checks if SOME_STRING exists in the binary file created.");
            Console.WriteLine("Example: pwned-passwords-ordered-2.0.txt -optimize pwned-passwords-ordered-2.0.bin");
            Console.WriteLine("Example: pwned-passwords-ordered-2.0.bin -check Passw0rd");
        }

        private static bool Lookup(Stream fileStream, string pass)
        {
            byte[] hash = s_hasher.ComputeHash(Encoding.UTF8.GetBytes(pass));
            using (var fileReader = new BinaryReader(fileStream))
            {
                return FindHash(fileReader, 0, fileReader.BaseStream.Length, hash.AsSpan());
            }
        }

        private static bool FindHash(BinaryReader fileReader, long startPos, long endPos, ReadOnlySpan<byte> hash)
        {
            if (startPos >= endPos)
            {
                return false;
            }

            int stride = 24;
            long count = (endPos - startPos) / stride;
            Span<byte> compare = stackalloc byte[stride];

            long middle = (int)(count / 2.0);
            long readPos = startPos + (middle * stride);
            fileReader.BaseStream.Seek(readPos, SeekOrigin.Begin);
            fileReader.Read(compare);
            int result = hash.SequenceCompareTo(compare.Slice(0, 20));
            if (result == 0)
            {
                return true;
            }
            else if (result > 0)
            {
                return FindHash(fileReader, fileReader.BaseStream.Position, endPos, hash);
            }

            return FindHash(fileReader, startPos, readPos, hash);
        }

        private static void PrintProgress(float progress)
        {
            Console.Write($"{(progress),6:N2}%");
            Console.SetCursorPosition(0, Console.CursorTop);
        }

        private static void ConvertToBinary(Stream stream, string outputFileName)
        {
            byte[] lookup = CreateHexLookup();
            var writer = new BinaryWriter(File.Open(outputFileName, FileMode.Create));
            int count = 0;
            byte[] buffer = new byte[63 * 1000];
            byte[] hash = new byte[20];

            while (stream.Position < stream.Length)
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                ReadOnlySpan<byte> readOnly = buffer.AsSpan();
                if (bytesRead % 63 != 0)
                {
                    throw new InvalidOperationException("Invalid number of bytes read");
                }

                for (int i = 0; i < bytesRead; i += 63)
                {
                    var hashEntry = readOnly.Slice(i, 63);
                    for (int j = 0; j < 20; j++)
                    {
                        hash[j] = (byte)((lookup[hashEntry[j * 2]] << 4) + lookup[hashEntry[j * 2 + 1]]);
                    }

                    Debug.Assert(string.Join("", hash.Select(x => x.ToString("X2"))) == Encoding.UTF8.GetString(readOnly.Slice(i, 40)));

                    writer.Write(hash);

                    if (Utf8Parser.TryParse(hashEntry.Slice(41, 10), out int hashCount, out int _))
                    {
                        writer.Write(hashCount);
                    }

                    if ((count % 10_000_00) == 0)
                    {
                        PrintProgress((stream.Position / (float)stream.Length) * 100);
                    }
                    count++;
                }
            }
            PrintProgress(100);
            writer.Close();
        }

        private static byte[] CreateHexLookup()
        {
            byte[] lookup = new byte[256];
            for (int i = 0; i <= 255; i++)
            {
                if (i >= 48 && i <= 57)
                {
                    lookup[i] = (byte)(i - 48);
                }
                else if (i >= 65 && i <= 70)
                {
                    lookup[i] = (byte)(i - 55);
                }
                else if (i >= 97 && i <= 102)
                {
                    lookup[i] = (byte)(i - 87);
                }
            }

            return lookup;
        }
    }
}
