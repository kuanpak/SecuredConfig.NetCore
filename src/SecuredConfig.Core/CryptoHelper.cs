using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace SecuredConfig.Core
{
    public class CryptoHelper
    {
        
        // RSA cert encrypted pattern: {Enc:[cert subject]:[base64 encrypted string]}
        public const string CertEncryptPrefix = "{Enc:";
        public const string CertEncryptSuffix = "}";

        private readonly ICertificateProvider certificateProvider;



        public CryptoHelper(ICertificateProvider certificateProvider)
        {
            this.certificateProvider = certificateProvider;
        }



        /// <summary>
        /// Use RSA private key to decrypt the ciper bytes with OAEP SHA256 padding.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public string DecryptStringFromBytes(byte[] cipherText, RSA rsa)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));

            if (rsa == null) 
                throw new ArgumentNullException(nameof(rsa));


            byte[] decrypted = rsa.Decrypt(cipherText, RSAEncryptionPadding.OaepSHA256);
            string plaintext = Encoding.UTF8.GetString(decrypted);

            return plaintext;
        }

        /// <summary>
        /// Interpert potential encrypted string by pattern matching.
        /// </summary>
        /// <param name="maybeEncrypted">String may contain encrypted values.</param>
        /// <returns>The decrypted string or non-encrypted string.</returns>
        /// <exception cref="CryptographicException"></exception>
        public string DecryptOrBypass(string maybeEncrypted)
        {
            if (maybeEncrypted == null) return null;

            if (maybeEncrypted.Length <= CertEncryptPrefix.Length)  // shorter than encryption header
            {
                return maybeEncrypted; // it is not encrypted, so just return
            }


            string certPattern = $"{Regex.Escape(CertEncryptPrefix)}(?<certTitle>((?!:).)*):(?<cipherText>((?!{Regex.Escape(CertEncryptSuffix)}).)*){Regex.Escape(CertEncryptSuffix)}";
            string result = Regex.Replace(maybeEncrypted, certPattern, (match) =>
            {
                string title = match.Groups["certTitle"].Value;
                string realEncryptedStr = match.Groups["cipherText"].Value;
                byte[] realEncryptedData = Convert.FromBase64String(realEncryptedStr);
                var cert = certificateProvider.GetCertificate(title);
                if (!cert.HasPrivateKey)
                    throw new CryptographicException($"There is no private key inside certificate {cert.Subject}, Thumbprint: {cert.Thumbprint}");
                using var rsa = cert.GetRSAPrivateKey();
                return DecryptStringFromBytes(realEncryptedData, rsa);
            });

            return result;
        }


        
        /// <summary>
        /// Use RSA public key to encrypt the given plain text to cipher bytes with OAEP SHA256 padding.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="rsa"></param>
        /// <returns></returns>
        public byte[] EncryptStringToBytes(string plainText, RSA rsa)
        {
            return rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
        }


        /// <summary>
        /// Use RSA public key by given certificate to encrypt the given plain text to cipher text with our defined pattern.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cert"></param>
        /// <returns></returns>
        public string EncryptWithHeader(string plainText, X509Certificate2 cert)
        {
            using var rsa = cert.GetRSAPublicKey();
            byte[] encrypted = EncryptStringToBytes(plainText, rsa); //RSA encrypt
            string title = certificateProvider.GetCertificateTitle(cert);
            return $"{CertEncryptPrefix}{title}:{Convert.ToBase64String(encrypted)}{CertEncryptSuffix}";
        }

        
    }
}
