using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class Aes256
{
    private const int KeyLength = 32;
    private const int AuthKeyLength = 64;
    private const int IvLength = 16;
    private const int HmacSha256Length = 32;

    private readonly byte[] _key;
    private readonly byte[] _authKey;

    private static readonly byte[] Salt =
    {
        0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B,
        0xB2, 0x19, 0x02, 0x24, 0x30, 0xA5, 0x78, 0x43,
        0x00, 0x3D, 0x56, 0x44, 0xD2, 0x1E, 0x62, 0xB9,
        0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41
    };

    public Aes256(string masterKey)
    {
        using (var derive = new Rfc2898DeriveBytes(masterKey, Salt, 50000))
        {
            _key = derive.GetBytes(KeyLength);
            _authKey = derive.GetBytes(AuthKeyLength);
        }
    }

    public string Decrypt(string input)
    {
        return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(input)));
    }

    public byte[] Decrypt(byte[] input)
    {
        using (var ms = new MemoryStream(input))
        using (var aesProvider = new AesCryptoServiceProvider())
        {
            aesProvider.KeySize = 256;
            aesProvider.BlockSize = 128;
            aesProvider.Mode = CipherMode.CBC;
            aesProvider.Padding = PaddingMode.PKCS7;
            aesProvider.Key = _key;

            using (var hmac = new HMACSHA256(_authKey))
            {
                byte[] hash = hmac.ComputeHash(
                    input,
                    HmacSha256Length,
                    input.Length - HmacSha256Length
                );

                byte[] receivedHash = new byte[HmacSha256Length];
                ms.Read(receivedHash, 0, receivedHash.Length);

                if (!FixedTimeEquals(hash, receivedHash))
                    throw new CryptographicException("Invalid MAC.");
            }

            byte[] iv = new byte[IvLength];
            ms.Read(iv, 0, iv.Length);
            aesProvider.IV = iv;

            using (var cs = new CryptoStream(ms, aesProvider.CreateDecryptor(), CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                cs.CopyTo(output);
                return output.ToArray();
            }
        }
    }

    private static bool FixedTimeEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length)
            return false;

        int diff = 0;
        for (int i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];

        return diff == 0;
    }
}
