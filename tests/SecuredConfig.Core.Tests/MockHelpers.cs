using Moq;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecuredConfig.Core.Tests
{
    public class MockHelpers
    {
        internal static ICertificateProvider GetMockCertificateProvider()
        {
            var mockProvider = new Mock<ICertificateProvider>();
            var rsa = RSA.Create(2048);
            CertificateRequest certReq = new CertificateRequest($"CN=unittest-mock", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            var title = new CertStoreCertificateProvider().GetCertificateTitle(cert);
            mockProvider.Setup(o => o.GetCertificate(It.IsAny<string>())).Throws<CertificateNotFoundException>();
            mockProvider.Setup(o => o.GetCertificate("CN=unittest-mock")).Returns(cert);
            mockProvider.Setup(o => o.GetCertificate(title)).Returns(cert);
            mockProvider.Setup(o => o.GetCertificateTitle(cert)).Returns(title);
            return mockProvider.Object;
        }

        internal static ICertificateProvider GetDummyCertificateProvider()
        {
            return new FileCertificateProvider("dummy.pfx");
            //var mockProvider = new Mock<ICertificateProvider>();
            //var cert = new X509Certificate2("dummy.pfx", "", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);

            //mockProvider.Setup(o => o.GetCertificate(It.IsAny<string>())).Throws<CertificateNotFoundException>();
            //mockProvider.Setup(o => o.GetCertificate("CN=dummy,NotAfter=2033-04-25")).Returns(cert);
            //mockProvider.Setup(o => o.GetCertificateTitle(cert)).Returns("CN=dummy,NotAfter=2033-04-25");
            //return mockProvider.Object;
        }
    }
}
