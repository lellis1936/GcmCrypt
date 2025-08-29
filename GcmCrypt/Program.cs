using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.IO.Compression;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
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
        const int V1_HEADER_LENGTH = 74;

        static readonly byte[] HEADER_NONCE = Enumerable.Repeat((byte)0xff, NONCE_LENGTH).ToArray();
        static readonly byte[] FEK_NONCE = Enumerable.Repeat((byte)0x00, NONCE_LENGTH).ToArray();
        static readonly byte[] NO_DATA = new byte[0];

        const string APP_VERSION = "1.2.1"; // app/CLI version
        const byte VERSION_MAJOR = 1;
        const byte VERSION_MINOR = 2;
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
            string version = APP_VERSION;
            Console.WriteLine($"GcmCrypt v{version}");
            Console.WriteLine("Usage is : ");
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

                sw.Start();
                Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
                byte[] key1 = k1.GetBytes(32);

                Console.WriteLine($"Key derivation took {sw.ElapsedMilliseconds} ms");

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

                    // Build the file header in memory and calculate a tag for it
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

                    // Now get the encryption done (streaming pipeline if compression enabled).
                    sw.Restart();
                    if (compression)
                    {
                        using (var pcs = new ProducerConsumerStream())
                        {
                            // Producer: compress input into pcs
                            var writerTask = Task.Run(() =>
                            {
                                try
                                {
                                    using (var gzs = new GZipStream(pcs, CompressionMode.Compress, leaveOpen: true))
                                    {
                                        fsIn.CopyTo(gzs);
                                    }
                                }
                                finally
                                {
                                    pcs.Close(); // always signal end of stream, even on error
                                }
                            });

                            // Consumer: encrypt from pcs into fsOut
                            ChunkedEncrypt(key2, CHUNK_SIZE, pcs, fsOut);

                            writerTask.Wait();
                        }
                    }
                    else
                    {
                        ChunkedEncrypt(key2, CHUNK_SIZE, fsIn, fsOut);
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
                    int PBKDF2iterations;

                    int headerLength;
                    var headerTag = new byte[TAG_LENGTH];

                    fsIn.ForceRead(sig, 0, sig.Length);
                    fsIn.ForceRead(versionMajor, 0, versionMajor.Length);
                    fsIn.ForceRead(versionMinor, 0, versionMinor.Length);

                    if (!sig.SequenceEqual(expectedSig)
                    || (versionMajor[0] != 1)
                    || (versionMinor[0] != 1 && versionMinor[0] != 2))
                    {
                        Console.WriteLine("Unsupported input file version");
                        return;
                    }
                    else
                    {
                        headerLength = V1_HEADER_LENGTH;
                    }

                    PBKDF2iterations = versionMinor[0] == 1 ? 10000 : 100000;

                    // Read in rest of V1.0 header pieces
                    fsIn.ForceRead(salt, 0, salt.Length);
                    fsIn.ForceRead(key2Encrypted, 0, key2Encrypted.Length);
                    fsIn.ForceRead(key2EncryptedTag, 0, key2EncryptedTag.Length);
                    fsIn.ForceRead(compressed, 0, compressed.Length);
                    fsIn.ForceRead(BEchunkSize, 0, BEchunkSize.Length);

                    // But then read full header in one chunk, and then tag, to authenticate it before continuing
                    var header = new byte[headerLength];
                    fsIn.Position = 0;
                    fsIn.ForceRead(header, 0, headerLength);
                    fsIn.ForceRead(headerTag, 0, headerTag.Length);

                    sw.Start();
                    Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(password, salt, PBKDF2iterations, HashAlgorithmName.SHA256);
                    byte[] key1 = k1.GetBytes(32);
                    Console.WriteLine($"Key derivation took {sw.ElapsedMilliseconds} ms");

                    GcmDecrypt(NO_DATA, key1, HEADER_NONCE, headerTag, header);

                    byte[] key2 = GcmDecrypt(key2Encrypted, key1, FEK_NONCE, key2EncryptedTag);

                    int chunkSize = BigEndianBytesToInt(BEchunkSize);
                    bool compression = compressed[0] == 1;

                    using (FileStream fsOut = new FileStream(outputFile, FileMode.Create, FileAccess.Write, FileShare.None, BUFFER_SIZE))
                    {
                        sw.Restart();
                        if (compression)
                        {
                            using (var pcs = new ProducerConsumerStream()) // compressed plaintext producer
                            {
                                // Producer: decrypt compressed bytes into pcs
                                var writerTask = Task.Run(() =>
                                {
                                    try
                                    {
                                        ChunkedDecrypt(key2, chunkSize, fsIn, pcs);
                                    }
                                    finally
                                    {
                                        pcs.Close(); // signal end-of-stream to reader
                                    }
                                });

                                // Consumer: GZipStream reads compressed bytes from pcs and writes decompressed to fsOut
                                using (var gzs = new GZipStream(pcs, CompressionMode.Decompress, leaveOpen: false))
                                {
                                    gzs.CopyTo(fsOut);
                                }

                                writerTask.Wait();
                            }
                        }
                        else
                        {
                            ChunkedDecrypt(key2, chunkSize, fsIn, fsOut);
                        }
                        sw.Stop();
                        Console.WriteLine("File decrypted successfully. AES GCM decryption took {0} ms.", sw.ElapsedMilliseconds);
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
                    // Some, or all of the tag is at the end of the data buffer
                    // Fix the tag and extract the ciphertext

                    if (bytesRead < tag.Length)
                        throw new CryptographicException("Encryped file is corrupt");

                    int ciphertextLen = bytesRead + tagBytesRead - tag.Length;
                    int tagDeficit = tag.Length - tagBytesRead;

                    Array.Copy(tag, 0, tag, tagDeficit, tagBytesRead);      // move tag bytes read to tail of tag
                    Array.Copy(buffer, ciphertextLen, tag, 0, tagDeficit);  // bring over the deficit
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

    // Simple producer–consumer bridge so GZip (write-only when compressing) can feed
    // ChunkedEncrypt/ChunkedDecrypt (readers) without buffering entire content.
    public class ProducerConsumerStream : Stream
    {
        private readonly BlockingCollection<byte[]> _buffers = new BlockingCollection<byte[]>();
        private byte[] _currentBuffer;
        private int _currentOffset;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count == 0) return;
            var chunk = new byte[count];
            Buffer.BlockCopy(buffer, offset, chunk, 0, count);
            _buffers.Add(chunk);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_currentBuffer == null || _currentOffset >= _currentBuffer.Length)
            {
                if (!_buffers.TryTake(out _currentBuffer, Timeout.Infinite))
                    return 0; // completed
                _currentOffset = 0;
            }

            int toCopy = Math.Min(count, _currentBuffer.Length - _currentOffset);
            Buffer.BlockCopy(_currentBuffer, _currentOffset, buffer, offset, toCopy);
            _currentOffset += toCopy;
            return toCopy;
        }

        public override void Flush() { }

        public override void Close()
        {
            _buffers.CompleteAdding();
            base.Close();
        }

        // Not supported
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    static class MyExtensions
    {
        public static int ForceRead(this Stream stream, byte[] data, int offset, int length)
        {
            // Guarantee all bytes of the data array are returned unless EOF reached first.
            // Often a BinaryReader is used, but note only BinaryReader.ReadBytes guarantees a full buffer.
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
