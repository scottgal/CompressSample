using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CompressSample
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 1)
            {
                var stringToCompress = args[0];
                var password = args[1];
                var encryptedString = stringToCompress.EncryptAndCompressString(password);
            Console.WriteLine($"Encrypted And Compressed String: {encryptedString}");
                Console.WriteLine($"Decrypted And Decompressed String: {encryptedString.DecryptAndDecompress(password).DecryptedString}");
            }
        }
    }
}
