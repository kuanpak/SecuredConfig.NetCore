using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecuredConfig.Core
{
    public class FileCertificateProvider : ICertificateProvider
    {
        private readonly string _filePath;
        private readonly string _password;
        private readonly X509Certificate2 _certificate;

        public X509Certificate2 Certificate => _certificate;

        public FileCertificateProvider(string filePath, string password = null)
        {
            _filePath = filePath;
            _password = password;
            _certificate = new X509Certificate2(_filePath, _password, X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet);
        }

        public X509Certificate2 GetCertificate(string title)
        {
            string certTitle = GetCertificateTitle(_certificate);
            if (certTitle.ToLower() != title.ToLower())
                throw new CertificateNotFoundException($"Certificate title '{certTitle}' not matched by the given title '{title}'");
            return _certificate;
        }

        public string GetCertificateTitle(X509Certificate2 cert)
        {
            return cert.GetCertificateTitle();
        }

    }
}
