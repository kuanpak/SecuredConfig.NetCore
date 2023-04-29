using FluentAssertions;
using Moq;
using Moq.Protected;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecuredConfig.Core.Tests;
using Xunit;

namespace SecuredConfig.Core.Json.Tests
{
    public class CryptoHelperTests
    {
        [Fact()]
        public void Encrypt_with_header_using_dummy_cert()
        {
            //Arrange
            var certificateProvider = MockHelpers.GetDummyCertificateProvider();
            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);
            var cert = certificateProvider.GetCertificate("CN=dummy,NotAfter=2033-04-25");

            string plainText = "plainValue1";

            //Act
            using var rsaEncryptor = cert.GetRSAPublicKey();
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, cert);

            //Assert
            encrypted.Should().NotBe(plainText);
            encrypted.Should().StartWith(CryptoHelper.CertEncryptPrefix).And.EndWith(CryptoHelper.CertEncryptSuffix);
        }

        [Fact()]
        public void Encrypt_Decrypt_with_header_using_RSA()
        {
            //Arrange
            var certificateProvider = MockHelpers.GetMockCertificateProvider();
            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);
            var cert = certificateProvider.GetCertificate("CN=unittest-mock");

            string plainText = "my中文plaintext";

            //Act
            using var rsaEncryptor = cert.GetRSAPublicKey();
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, cert);

            //Assert
            encrypted.Should().NotBe(plainText);
            encrypted.Should().StartWith(CryptoHelper.CertEncryptPrefix).And.EndWith(CryptoHelper.CertEncryptSuffix);

            //Act more for decryption
            using var rsaDecryptor = cert.GetRSAPrivateKey();
            string decrypted = cryptoHelper.DecryptOrBypass(encrypted);

            //Assert
            decrypted.Should().Be(plainText);
        }

        [Fact()]
        public void Decrypt_multiple_encrypted_values_Test()
        {
            //Arrange
            var mockCertProvider = MockHelpers.GetMockCertificateProvider();

            CryptoHelper cryptoHelper = new CryptoHelper(mockCertProvider);

            string plainText = "plainValue1";   //plain text to be encrypted
            string plainText2 = "plainValue2";   //plain text 2 to be encrypted

            //Act
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, mockCertProvider.GetCertificate("CN=unittest-mock"));
            string encrypted2 = cryptoHelper.EncryptWithHeader(plainText2, mockCertProvider.GetCertificate("CN=unittest-mock"));
            string mixed = $"field1={encrypted}; field2={encrypted2}";
            string decrypted = cryptoHelper.DecryptOrBypass(mixed);

            //Assert
            decrypted.Should().NotBeEquivalentTo(mixed, because: "mixed string contains encrypted values");
            decrypted.Should().Be("field1=plainValue1; field2=plainValue2");
        }

        [Fact()]
        public void Decrypt_non_encrypted_string_should_bypass()
        {
            //Arrange
            var mockCertProvider = MockHelpers.GetMockCertificateProvider();

            CryptoHelper cryptoHelper = new CryptoHelper(mockCertProvider);

            string mayBeEncrypted = "non-encrypted-value";

            //Act
            string decrypted = cryptoHelper.DecryptOrBypass(mayBeEncrypted);

            //Assert
            decrypted.Should().Be(mayBeEncrypted, "By pass the decryption if there is no encrypted value pattern");
        }


        [Fact()]
        public void Encrypt_Decrypt_using_certificate_publickey_by_subject()
        {
            //Arrange
            var rsa = RSA.Create(2048);
            string guid = Guid.NewGuid().ToString().ToLower();
            CertificateRequest certReq = new CertificateRequest($"cn=unittest-{guid}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            string subject = $"cn=unittest-{guid}";
            string storeName = "UnitTest";
            var store = new X509Store(storeName, StoreLocation.CurrentUser);
            X509Certificate2 certWithPrivateKey = new X509Certificate2(cert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet); //need to export to pfx then imort as another cert, otherwise the private key will not be stored.
            try
            {
                store.Open(OpenFlags.ReadWrite);

                store.Add(certWithPrivateKey);


                Environment.SetEnvironmentVariable("CRYPTO_CERTIFICATE_STORE", storeName, EnvironmentVariableTarget.Process);


                CryptoHelper cryptoHelper = CreateCryptoHelper();

                string plainText = "my中文plaintext";

                //Act
                string encrypted = cryptoHelper.EncryptWithHeader(plainText, cert);

                //Assert
                encrypted.Should().NotBe(plainText);
                encrypted.Should().StartWith(CryptoHelper.CertEncryptPrefix).And.EndWith(CryptoHelper.CertEncryptSuffix);

                //Act more for decryption
                string decrypted = cryptoHelper.DecryptOrBypass(encrypted);

                //Assert
                decrypted.Should().Be(plainText);
            }
            finally
            {
                store.Remove(certWithPrivateKey);
                store.Dispose();
                Environment.SetEnvironmentVariable("CRYPTO_CERTIFICATE_STORE", null, EnvironmentVariableTarget.Process);
            }
        }

        [Fact()]
        public void Decrypt_with_non_exist_certificate_should_throw_error()
        {

            CryptoHelper cryptoHelper = CreateCryptoHelper();

            Assert.Throws<CertificateNotFoundException>(() =>
            {
                cryptoHelper.DecryptOrBypass("{Enc:CN=notexist:" + Convert.ToBase64String(Encoding.UTF8.GetBytes("dummy base64 content")) + "}");
            });

        }

        [Fact()]
        public void Decrypt_non_encrypted_string_using_non_exist_certificate_should_bypass()
        {
            //Arrange
            string unencrypted = "non-encrypted-value";


            // Act
            CryptoHelper cryptoHelper = CreateCryptoHelper();
            var decrypted = cryptoHelper.DecryptOrBypass(unencrypted);

            //Assert
            decrypted.Should().Be(unencrypted, "Not throwing exception even certificate not exist if there is no encrypted value pattern");
        }


        [Fact()]
        public void Encrypt_Decrypt_using_RSA_without_PrivateKey_Should_ThrowsError()
        {
            //Arrange
            var rsa = RSA.Create(2048);
            CertificateRequest certReq = new CertificateRequest($"CN=unittest-mock", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            X509Certificate2 certNoPrivateKey = new X509Certificate2(cert.Export(X509ContentType.Cert), "", X509KeyStorageFlags.UserKeySet);

            var certificateProvider = GetMockCertificateProvider(certNoPrivateKey);
            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);
            

            string plainText = "my中文plaintext";

            //Act
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, certNoPrivateKey);

            //Assert
            encrypted.Should().NotBe(plainText);
            encrypted.Should().StartWith(CryptoHelper.CertEncryptPrefix).And.EndWith(CryptoHelper.CertEncryptSuffix);

            //Act more for decryption
            using var rsaDecryptor = certNoPrivateKey.GetRSAPrivateKey();
            rsaDecryptor.Should().BeNull(because: "there is no private key in the cert");

            //Assert
            Assert.Throws<CryptographicException>(() =>
            {
                string decrypted = cryptoHelper.DecryptOrBypass(encrypted);
            });
        }

        [Fact()]
        public void Encrypt_Decrypt_using_RSA_with_subject_contains_colon()
        {
            //Arrange
            var rsa = RSA.Create(2048);
            CertificateRequest certReq = new CertificateRequest($"CN=unittest:mock", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            X509Certificate2 certWithPrivateKey = new X509Certificate2(cert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);

            var certificateProvider = GetMockCertificateProvider(certWithPrivateKey);
            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);


            string plainText = "my中文plaintext";

            //Act
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, certWithPrivateKey);

            //Assert
            encrypted.Should().NotBe(plainText);
            encrypted.Should().StartWith(CryptoHelper.CertEncryptPrefix).And.EndWith(CryptoHelper.CertEncryptSuffix);

            //Act more for decryption
            using var rsaDecryptor = certWithPrivateKey.GetRSAPrivateKey();
            rsaDecryptor.Should().NotBeNull(because: "there is private key in the cert");

            //Assert
            
            string decrypted = cryptoHelper.DecryptOrBypass(encrypted);
            decrypted.Should().Be(plainText);
        }



        private ICertificateProvider GetMockCertificateProvider(X509Certificate2 cert)
        {
            var mockProvider = new Mock<ICertificateProvider>();

            mockProvider.Setup(o => o.GetCertificate(It.IsAny<string>())).Throws<CertificateNotFoundException>();
            string normalizedSub = new CertStoreCertificateProvider().GetCertificateTitle(cert);
            mockProvider.Setup(o => o.GetCertificate(normalizedSub)).Returns(cert);
            mockProvider.Setup(o => o.GetCertificateTitle(cert)).Returns(normalizedSub);
            return mockProvider.Object;
        }

        private static CryptoHelper CreateCryptoHelper()
        {
            CertStoreCertificateProvider certificateProvider = new CertStoreCertificateProvider();

            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);
            return cryptoHelper;
        }
    }
}