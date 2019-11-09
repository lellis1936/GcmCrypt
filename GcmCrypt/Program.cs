using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.IO.Compression;
using System.CodeDom.Compiler;
using System.Diagnostics;
using static AESGCM;

namespace GcmCrypt
{
    class Program
    {
        const int BUFFER_SIZE = 64 * 1024;
        const int CHUNK_SIZE = 64 * 1024;           //not currently configurable for encryption
        const int NONCE_LENGTH = 12;
        const int KEY_LENGTH = 32;
        const int TAG_LENGTH = 16;
        const int SALT_LENGTH = 16;
        const int V1_1_HEADER_LENGTH = 74;

        static readonly byte[] HEADER_NONCE = Enumerable.Repeat((byte)0xff, NONCE_LENGTH).ToArray();
        static readonly byte[] FEK_NONCE = Enumerable.Repeat((byte)0x00, NONCE_LENGTH).ToArray();
        static readonly byte[] NO_DATA = new byte[0];

        const byte VERSION_MAJOR = 1;
        const byte VERSION_MINOR = 1;
        static void Main(string[] args)
        {
            bool encrypting = false;
            bool decrypting = false;
            bool compress = false;
            bool forceOverwrite = false;
            string password = "";
            string inFile = "";
            string outFile = "";

            int parmCount = 0;
            foreach (string arg in args)
            {
                if (arg.StartsWith("-"))
                {
                    switch (arg.ToLower())
                    {
                        case "-e": encrypting = true; break;
                        case "-d": decrypting = true; break;
                        case "-f": forceOverwrite = true; break;
                        case "-compress": compress = true; break;
                    }
                }
                else
                {
                    ++parmCount;
                    if (parmCount == 1)
                        password = arg;
                    else if (parmCount == 2)
                        inFile = arg;
                    else if (parmCount == 3)
                        outFile = arg;
                }
            }

            if ((encrypting && decrypting) || (!encrypting && !decrypting))
            {
                PrintUsage();
                return;
            }

            if (parmCount != 3)
            {
                PrintUsage();
                return;
            }


            if (!forceOverwrite)
            {
                if (File.Exists(outFile))
                {
                    if (!PromptConfirmation("Output file already exists.  Do you want to overwrite it?"))
                        return;
                }
            }

            if (encrypting)
                EncryptFile(password, inFile, outFile, compress);
            else
                DecryptFile(password, inFile, outFile);

        }

        static void PrintUsage()
        {
            Console.WriteLine("GcmCrypt usage is : ");
            Console.WriteLine("\tGcmCrypt -e|-d [-f] [-compress] password infile outfile. ");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("\tGcmCrypt -e -compress mypass myinputfile myencryptedoutputfile");
            Console.WriteLine("\tGcmCrypt -d mypass myencryptedinputfile mydecryptedoutputfile");
            Console.WriteLine();
            Console.WriteLine("\n-compress option only needed for encryption");
            Console.WriteLine("\n-f option will silently overwrite the output file if it exists");
            Console.WriteLine();
        }

        private static void EncryptFile(string password, string inputFile, string outputFile, bool compression)
        {
            try
            {
                var sw = new Stopwatch();

                var rng = RNGCryptoServiceProvider.Create();

                var sig = Encoding.UTF8.GetBytes("GCM");
                var salt = new byte[SALT_LENGTH];
                var key2 = new byte[KEY_LENGTH];
                var key2Encrypted = new byte[KEY_LENGTH];
                rng.GetBytes(salt);
                rng.GetBytes(key2);

                Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
                byte[] key1 = k1.GetBytes(32);

                byte[] key2EncryptedTag = new byte[TAG_LENGTH];
                key2Encrypted = GcmEncrypt(key2, key1, FEK_NONCE, key2EncryptedTag);

                using (FileStream fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, BUFFER_SIZE))
                using (FileStream fsOut = new FileStream(outputFile, FileMode.Create, FileAccess.ReadWrite, FileShare.None, BUFFER_SIZE))
                {
                    var compressed = new byte[1] { (byte)(compression ? 1 : 0) };
                    var BEchunkSize = BigEndianBytesFromInt(CHUNK_SIZE);
                    var versionMajor = new byte[] { VERSION_MAJOR };
                    var versionMinor = new byte[] { VERSION_MINOR };

                    byte[] header;
                    var headerTag = new byte[TAG_LENGTH];

                    //Build the file header in memory and calculate a tag for it
                    using (MemoryStream ms = new MemoryStream())
                    {
                        ms.Write(sig, 0, sig.Length);                           //3
                        ms.Write(versionMajor, 0, versionMajor.Length);         //1
                        ms.Write(versionMinor, 0, versionMinor.Length);         //1
                        ms.Write(salt, 0, salt.Length);                         //16
                        ms.Write(key2Encrypted, 0, key2Encrypted.Length);       //32
                        ms.Write(key2EncryptedTag, 0, key2EncryptedTag.Length); //16
                        ms.Write(compressed, 0, compressed.Length);             //1
                        ms.Write(BEchunkSize, 0, BEchunkSize.Length);           //4
                        header = ms.ToArray();
                        GcmEncrypt(NO_DATA, key1, HEADER_NONCE, headerTag, header);
                    }

                    fsOut.Write(header, 0, header.Length);
                    fsOut.Write(headerTag, 0, headerTag.Length);

                    //Now get the encryption done.
                    using (var ms = new MemoryStream())
                    using (GZipStream gstr = compression ? new GZipStream(ms, CompressionMode.Compress, true) : null)
                    {
                        sw.Start();
                        if (compression)
                        {
                            fsIn.CopyTo(gstr);
                            gstr.Close();                                       //Must close!! Flush will not do it!
                            ms.Position = 0;
                            ChunkedEncrypt(key2, CHUNK_SIZE, ms, fsOut);
                        }
                        else
                        {
                            ChunkedEncrypt(key2, CHUNK_SIZE, fsIn, fsOut);
                        }
                    }
                }
                sw.Stop();
                Console.WriteLine("File encrypted. AES GCM encryption took {0} ms", sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption failed: {ex.Message}");
            }
        }


        private static void DecryptFile(string password, string inputFile, string outputFile)
        {
            try
            {
                var sw = new Stopwatch();
                using (FileStream fsIn = new FileStream(inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, BUFFER_SIZE))
                {
                    var sig = new byte[3];
                    var expectedSig = Encoding.UTF8.GetBytes("GCM");
                    var versionMajor = new byte[1];
                    var versionMinor = new byte[1];
                    var salt = new byte[SALT_LENGTH];
                    var key2Encrypted = new byte[KEY_LENGTH];
                    var key2EncryptedTag = new byte[TAG_LENGTH];
                    var compressed = new byte[1];
                    var BEchunkSize = new byte[4];

                    int headerLength;
                    var headerTag = new byte[TAG_LENGTH];

                    fsIn.ForceRead(sig, 0, sig.Length);
                    fsIn.ForceRead(versionMajor, 0, versionMajor.Length);
                    fsIn.ForceRead(versionMinor, 0, versionMinor.Length);
                    if (!sig.SequenceEqual(expectedSig)
                    || versionMajor[0] != 1
                    || versionMinor[0] != 1)
                    {
                        Console.WriteLine("Unsupported input file version");
                        return;
                    }
                    else
                    {
                        headerLength = V1_1_HEADER_LENGTH;
                    }

                    //Read in rest of V1.0 header pieces
                    fsIn.ForceRead(salt, 0, salt.Length);
                    fsIn.ForceRead(key2Encrypted, 0, key2Encrypted.Length);
                    fsIn.ForceRead(key2EncryptedTag, 0, key2EncryptedTag.Length);
                    fsIn.ForceRead(compressed, 0, compressed.Length);
                    fsIn.ForceRead(BEchunkSize, 0, BEchunkSize.Length);

                    //But then read full header in one chunk, and then tag,  to authenticate it before continuing
                    var header = new byte[headerLength];
                    fsIn.Position = 0;
                    fsIn.ForceRead(header, 0, headerLength);
                    fsIn.ForceRead(headerTag, 0, headerTag.Length);

                    Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
                    byte[] key1 = k1.GetBytes(32);

                    GcmDecrypt(NO_DATA, key1, HEADER_NONCE, headerTag, header);
                    
                    byte[] key2 = GcmDecrypt(key2Encrypted, key1, FEK_NONCE, key2EncryptedTag);

                    int chunkSize = BigEndianBytesToInt(BEchunkSize);
                    bool compression = compressed[0] == 1 ? true : false;

                    using (FileStream fsOut = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, BUFFER_SIZE))
                    using (var ms = new MemoryStream())
                    using (GZipStream gstr = compression ? new GZipStream(ms, CompressionMode.Decompress) : null)
                    {
                        sw.Start();
                        if (compression)
                        {
                            ChunkedDecrypt(key2, chunkSize, fsIn, ms);
                            ms.Position = 0;
                            gstr.CopyTo(fsOut);
                        }
                        else
                        {
                            ChunkedDecrypt(key2, chunkSize, fsIn, fsOut);
                        }
                        sw.Stop();
                        Console.WriteLine("File decrypted. AES GCM decryption took {0} ms", sw.ElapsedMilliseconds);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Decryption failed: {ex.Message}");
            }
        }
        private static bool PromptConfirmation(string confirmText)
        {
            ConsoleKey response;
            do
            {
                Console.Write(confirmText + " [y/n] : ");
                response = Console.ReadKey(false).Key;
                Console.WriteLine();
            } while (response != ConsoleKey.Y && response != ConsoleKey.N);

            return (response == ConsoleKey.Y);
        }

        private static void ChunkedEncrypt(byte[] key, int chunkSize, Stream input, Stream output)
        {
            int bytesRead;
            var tag = new byte[16];
            var nonce = new byte[12];
            var buffer = new byte[chunkSize];
            byte[] writebuf;

            while ((bytesRead = input.ForceRead(buffer, 0, buffer.Length)) != 0)
            {
                IncrementNonce(nonce);

                if (bytesRead < buffer.Length)
                    writebuf = Slice(buffer, 0, bytesRead);
                else
                    writebuf = buffer;

                var ciphertext = GcmEncrypt(writebuf, key, nonce, tag);
                output.Write(ciphertext, 0, ciphertext.Length);
                output.Write(tag, 0, tag.Length);
            }
        }

        private static void ChunkedDecrypt(byte[] key, int chunkSize, Stream input, Stream output)
        {
            int bytesRead;
            int tagBytesRead;
            var tag = new byte[TAG_LENGTH];
            var nonce = new byte[NONCE_LENGTH];
            var buffer = new byte[chunkSize];
            byte[] plaintext;

            while ((bytesRead = input.ForceRead(buffer, 0, buffer.Length)) != 0)
            {
                IncrementNonce(nonce);
                tagBytesRead = input.ForceRead(tag, 0, tag.Length);

                if (bytesRead == chunkSize && tagBytesRead == tag.Length)
                {
                    plaintext = GcmDecrypt(buffer, key, nonce, tag);
                    output.Write(plaintext, 0, plaintext.Length);
                }
                else
                {
                    //Some, or all of the tag is at the end of the data buffer
                    //Fix the tag and extract the ciphertext

                    if (bytesRead < tag.Length)
                        throw new CryptographicException("Encryped file is corrupt");

                    int ciphertextLen = bytesRead + tagBytesRead - tag.Length;
                    int tagDeficit = tag.Length - tagBytesRead;

                    Array.Copy(tag, 0, tag, tagDeficit, tagBytesRead);      //move tag bytes read to tail of tag
                    Array.Copy(buffer, ciphertextLen, tag, 0, tagDeficit);  //bring over the deficit
                    byte[] ciphertext = Slice(buffer, 0, ciphertextLen);
                    plaintext = GcmDecrypt(ciphertext, key, nonce, tag);
                    output.Write(plaintext, 0, plaintext.Length);
                    break;
                }
            }
        }

        private static void IncrementNonce(byte[] nonce)
        {
            for (var i = nonce.Length - 1; i >= 0; i--)
            {
                if (++nonce[i] != 0)
                    return;
            }
        }

        static byte[] Slice(byte[] input, int offset, int length)
        {
            if (input.Length == length)
                return input;

            byte[] output = new byte[length];
            Array.Copy(input, offset, output, 0, length);
            return output;
        }

        static byte[] BigEndianBytesFromInt(int value)
        {
            byte[] result = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(result);
            return result;
        }

        static int BigEndianBytesToInt(byte[] input)
        {
            byte[] value = (byte[])input.Clone();

            if (BitConverter.IsLittleEndian)
                Array.Reverse(value);

            return BitConverter.ToInt32(value, 0);

        }
    }

    static class MyExtensions
    {
        public static int ForceRead(this Stream stream, byte[] data, int offset, int length)
        {
            //Guarantee all bytes of the data array are returned unless EOF 
            //reached first.  Often a BinaryReader is used, but note only
            //BinaryReader.GetBytes, not BinaryReader.Read will guarantee
            //that the buffer is filled.
            int remaining = data.Length;
            int read = 0;
            while (remaining > 0 && (read = stream.Read(data, offset, remaining)) != 0)
            {
                remaining -= read;
                offset += read;
            }
            return length - remaining;
        }
    }
}
