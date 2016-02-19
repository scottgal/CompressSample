using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CompressSample
{

        public class DecryptResult
        {
            public string DecryptedString { get; set; }

            public bool IsDecrypted { get; set; }
        }

        public static class CryptoHelper
        {
            private static readonly byte[] Salt =
            {
            0x49, 0x46, 0x61, 0x6f, 0x21, 0x3d,
            0x65, 0xE4, 0x76, 0x95, 0x64, 0x65, 0x86
        };

        /// <summary>
        /// Optional start for the string which permits detection of encrypted files...
        /// </summary>
            private const string MapHeader = "";

        public static string EncryptAndCompressString(this string clearText, string password)
        {
            var mapText = clearText.Compress().Encrypt(password);
            return MapHeader + mapText;
        }

        public static bool IsEncryptedString(this string mapText)
        {
            if (string.IsNullOrEmpty(MapHeader)) return true;
            return mapText.StartsWith(MapHeader);
        }

        public static DecryptResult DecryptAndDecompress(this string mapText, string password)
        {
            var result = new DecryptResult();
            if (!mapText.IsEncryptedString())
            {
                result.IsDecrypted = false;
                result.DecryptedString = mapText;
            }
            var strippedMap = mapText.Substring(MapHeader.Length);
            try
            {
                result.DecryptedString = strippedMap.Decrypt(password).Decompress();
                result.IsDecrypted = true;
            }
            catch (Exception)
            {
                result.IsDecrypted = false;
            }

            return result;
        }

        public static string Compress(this string text)
            {
                var buffer = Encoding.UTF8.GetBytes(text);
                var ms = new MemoryStream();
                using (var zip = new GZipStream(ms, CompressionMode.Compress, true))
                {
                    zip.Write(buffer, 0, buffer.Length);
                }

                ms.Position = 0;

                var compressed = new byte[ms.Length];
                ms.Read(compressed, 0, compressed.Length);

                var gzBuffer = new byte[compressed.Length + 4];
                Buffer.BlockCopy(compressed, 0, gzBuffer, 4, compressed.Length);
                Buffer.BlockCopy(BitConverter.GetBytes(buffer.Length), 0, gzBuffer, 0, 4);
                return Convert.ToBase64String(gzBuffer);
            }

            public static string Decompress(this string compressedText)
            {
                var gzBuffer = Convert.FromBase64String(compressedText);
                using (var ms = new MemoryStream())
                {
                    var msgLength = BitConverter.ToInt32(gzBuffer, 0);
                    ms.Write(gzBuffer, 4, gzBuffer.Length - 4);

                    var buffer = new byte[msgLength];

                    ms.Position = 0;
                    using (var zip = new GZipStream(ms, CompressionMode.Decompress))
                    {
                        zip.Read(buffer, 0, buffer.Length);
                    }

                    return Encoding.UTF8.GetString(buffer);
                }
            }

           

            public static string Encrypt(this string clearText, string password)
            {
                var clearBytes = Encoding.Unicode.GetBytes(clearText);
                var pdb = new Rfc2898DeriveBytes(password,
                    Salt);

                var encryptedData = Encrypt(clearBytes,
                    pdb.GetBytes(32), pdb.GetBytes(16));

                return Convert.ToBase64String(encryptedData);
            }

            public static byte[] Encrypt(byte[] clearData, byte[] key, byte[] iv)
            {
                byte[] encryptedData;
                using (var ms = new MemoryStream())
                {
                    using (var alg = Rijndael.Create())
                    {
                        alg.Key = key;
                        alg.IV = iv;
                        using (var cs = new CryptoStream(ms,
                            alg.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(clearData, 0, clearData.Length);
                        }
                        encryptedData = ms.ToArray();
                    }
                }
                return encryptedData;
            }

            public static string Decrypt(this string cipherText, string password)
            {
                var cipherBytes = Convert.FromBase64String(cipherText);
                var pdb = new Rfc2898DeriveBytes(password, Salt);
                var decryptedData = Decrypt(cipherBytes,
                    pdb.GetBytes(32), pdb.GetBytes(16));
                return Encoding.Unicode.GetString(decryptedData);
            }

            public static byte[] Decrypt(byte[] cipherData, byte[] key, byte[] iv)
            {
                byte[] decryptedData;
                using (var ms = new MemoryStream())
                {
                    using (var alg = Rijndael.Create())
                    {
                        alg.Key = key;
                        alg.IV = iv;
                        using (var cs = new CryptoStream(ms,
                            alg.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherData, 0, cipherData.Length);
                        }
                        decryptedData = ms.ToArray();
                    }
                }
                return decryptedData;
            }
        }
    }

