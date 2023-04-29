using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecuredConfig.Core
{
    public interface ICertificateProvider
    {
        X509Certificate2 GetCertificate(string title);

        string GetCertificateTitle(X509Certificate2 cert);
    }
}
