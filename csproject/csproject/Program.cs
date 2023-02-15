using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace csproject
{
    class Program
    {
static void Main(string[] args)
        {
            string message;
             try
            {
            // Generate a new AES key
            Aes aes = Aes.Create();
            byte[] aesKey = aes.Key;

            // Generate a new RSA key pair
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] publicKey = rsa.ExportCspBlob(false);
            byte[] privateKey = rsa.ExportCspBlob(true);

            // Encrypt the AES key with the RSA public key
            byte[] encryptedAesKey = rsa.Encrypt(aesKey, false);

            // Get the message to encrypt
            Console.WriteLine("Enter a Secrete message");
            message = Console.ReadLine() ?? "";

            // Use the AES key to encrypt the data
            byte[] data = System.Text.Encoding.UTF8.GetBytes(message);
            (byte[] encryptedData , byte[] encryptedIv)= EncryptData(data, aesKey);

            Console.WriteLine("Encoding Secrete Message " + message + " ...");
            Console.WriteLine("Press Enter key to continue...");
            Console.ReadLine();

            Console.WriteLine("Encoded Data: " + Encoding.UTF8.GetString(encryptedData));

            // Use the RSA private key to decrypt the AES key
            byte[] decryptedAesKey = rsa.Decrypt(encryptedAesKey, false);

            // Use the decrypted AES key to decrypt the data
            byte[] decryptedData = DecryptData(encryptedData, decryptedAesKey, encryptedIv);

            // Display the decrypted data
            Console.WriteLine("Here is your Decrypted Message: " + System.Text.Encoding.UTF8.GetString(decryptedData));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        static (byte[], byte[]) EncryptData(byte[] data, byte[] key)
        {
            byte[] encriptedData;
            byte[] generatedIv;
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                generatedIv = aes.IV;

                Console.WriteLine("Key being passed to EncryptData function: " + System.Text.Encoding.UTF8.GetString(key));
                Console.WriteLine("Length of key being passed to EncryptData function: " + key.Length);
                Console.WriteLine("Data being passed to EncryptData function: " + System.Text.Encoding.UTF8.GetString(data));
                Console.WriteLine("Length of data being passed to EncryptData function: " + data.Length);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        Console.WriteLine("EncryptData Padding mode: " + aes.Padding);
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();

                        encriptedData = memoryStream.ToArray();
                        return (encriptedData, generatedIv);
                    }
                }
            }
        }

        static byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                Console.WriteLine("Key being passed to DecryptData function: " + System.Text.Encoding.UTF8.GetString(key));
                Console.WriteLine("Length of key being passed to DecryptData function: " + key.Length);
                Console.WriteLine("Data being passed to DecryptData function: " + System.Text.Encoding.UTF8.GetString(data));
                Console.WriteLine("Length of data being passed to DecryptData function: " + data.Length);

                using (MemoryStream memoryStream = new MemoryStream(data))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Read))
                    {
                        Console.WriteLine("Decryption Padding mode: " + aes.Padding);
                        using (MemoryStream outputStream = new MemoryStream())
                        {
                            cryptoStream.CopyTo(outputStream);
                            return outputStream.ToArray();
                        }
                    }
                }
            }
        }
    }
}
