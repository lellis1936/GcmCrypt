using System;
using System.Security.Cryptography;
using System.Text;
#if NETFRAMEWORK
using System.Runtime.InteropServices;
#endif

namespace GcmCrypt
{
    internal static class PasswordKeyDerivation
    {
        internal static byte[] DeriveKey(string password, byte[] salt, int iterations, int keyLength)
        {
#if NETFRAMEWORK
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] key = new byte[keyLength];
            IntPtr algorithmProvider;

            int status = BCryptOpenAlgorithmProvider(
                out algorithmProvider,
                "SHA256",
                null,
                BCRYPT_ALG_HANDLE_HMAC_FLAG);

            ThrowIfFailed(status, "BCryptOpenAlgorithmProvider");

            try
            {
                status = BCryptDeriveKeyPBKDF2(
                    algorithmProvider,
                    passwordBytes,
                    passwordBytes.Length,
                    salt,
                    salt.Length,
                    (ulong)iterations,
                    key,
                    key.Length,
                    0);

                ThrowIfFailed(status, "BCryptDeriveKeyPBKDF2");
                return key;
            }
            finally
            {
                BCryptCloseAlgorithmProvider(algorithmProvider, 0);
            }
#else
            using (var keyDerivation = new Rfc2898DeriveBytes(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA256))
            {
                return keyDerivation.GetBytes(keyLength);
            }
#endif
        }

#if NETFRAMEWORK
        private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(
            out IntPtr algorithmProvider,
            string algorithmId,
            string implementation,
            uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(
            IntPtr prf,
            byte[] password,
            int passwordLength,
            byte[] salt,
            int saltLength,
            ulong iterations,
            byte[] derivedKey,
            int derivedKeyLength,
            uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithmProvider, uint flags);

        private static void ThrowIfFailed(int status, string operation)
        {
            if (status != 0)
                throw new CryptographicException($"{operation} failed with status 0x{status:X8}");
        }
#endif
    }
}
