using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecuredConfig.Core
{
    public static class CertificateUtils
    {
        public static string GetCertificateTitle(this X509Certificate2 cert)
        {
            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            string title = $"CN={cn},NotAfter={cert.NotAfter.ToUniversalTime():yyyy-MM-dd}";
            return NormalizeTitle(title);
        }

        public static string NormalizeTitle(string title)
        {
            return title.Replace(':', '_');
        }
    }
}
