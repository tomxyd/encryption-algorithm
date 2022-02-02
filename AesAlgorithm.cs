using System;
using System.IO;
using System.Security.Cryptography;

namespace AesAlgorithmDemo
{
    public class AesExample
    {
        public void Init()
        {
            Console.WriteLine("Input a string to encrypt and decrypt");
            string? plain;
            plain = Console.ReadLine();

            using (Aes aes = Aes.Create())
            {
                // Encrypt the string
                byte[] encrypted = EncryptStringToBytes(plain, aes.Key, aes.IV);

                string roundtrip = DecryptStringFromBytes(encrypted, aes.Key, aes.IV);

                //Convert byte array to string

                var str = System.Text.Encoding.Default.GetString(encrypted);


                Console.WriteLine(str);
                Console.WriteLine(roundtrip);

            }
        }

        public byte[] EncryptStringToBytes(string txt, byte[] key, byte[] IV)
        {
            if (txt == null || txt.Length <= 0)
                throw new ArgumentNullException("Text is plain");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("Key is Empty");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV is Empty");
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(txt);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;

        }

        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}