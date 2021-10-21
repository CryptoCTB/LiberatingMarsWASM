using System;
using System.IO;
using System.Security.Cryptography;

namespace LiberatingMarsCLI
{
    class AES
    {
        public static byte[] AesCryptBytes(byte[] data, bool encrypt, byte[] AESKey, byte[] AESIV)
        {
            if (data.Length % 0x10 != 0)
            {
                byte[] temp = new byte[((data.Length / 0x10) + 1) * 0x10];
                Array.Copy(data, 0, temp, 0, data.Length);
                data = temp;
            }

            AesManaged aes = new AesManaged();
            aes.KeySize = 256;
            aes.Key = AESKey;
            aes.Padding = PaddingMode.None;
            aes.Mode = CipherMode.CBC;
            aes.IV = AESIV;
            ICryptoTransform cryptor = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();

            byte[] outputBuffer = null;
            using (MemoryStream msDecrypt = new MemoryStream(data))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, cryptor, CryptoStreamMode.Read))
                {
                    outputBuffer = new byte[data.Length];
                    csDecrypt.Read(outputBuffer, 0, data.Length);

                }
            }

            return outputBuffer;
        }
    }
}
