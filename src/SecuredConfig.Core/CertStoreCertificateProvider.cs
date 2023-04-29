using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecuredConfig.Core
{
    public class CertStoreCertificateProvider : ICertificateProvider
    {
        public X509Certificate2 GetCertificate(string title)
        {
            string certificateStoreName = Environment.GetEnvironmentVariable("CRYPTO_CERTIFICATE_STORE", EnvironmentVariableTarget.Process);
            if (string.IsNullOrEmpty(certificateStoreName))
            {
                certificateStoreName = Environment.GetEnvironmentVariable("CRYPTO_CERTIFICATE_STORE", EnvironmentVariableTarget.Machine);
                if (string.IsNullOrEmpty(certificateStoreName))
                {
                    certificateStoreName = Environment.GetEnvironmentVariable("CRYPTO_CERTIFICATE_STORE", EnvironmentVariableTarget.User);
                    if (string.IsNullOrEmpty(certificateStoreName))
                        certificateStoreName = "My";
                }
            }

            string certificateTitle = title;

            //open LocalMachine store can only work on Windows. Linux or MacOS will throw exception.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                //search certificate from Machine cert store
                using (X509Store x509Store = new X509Store(certificateStoreName, StoreLocation.LocalMachine))
                {
                    x509Store.Open(OpenFlags.ReadOnly);
                    
                    foreach (var certificate in x509Store.Certificates)
                    {
                        if (GetCertificateTitle(certificate).ToLower() == certificateTitle.ToLower())
                        {
                            return certificate;
                        }
                    }
                }
            }

            //search certificate from Current User cert store if certificate could not be found in Machine store.
            using (X509Store userStore = new X509Store(certificateStoreName, StoreLocation.CurrentUser))
            {
                userStore.Open(OpenFlags.ReadOnly);
                
                foreach (var certificate in userStore.Certificates)
                {
                    if (GetCertificateTitle(certificate).ToLower() == certificateTitle.ToLower())
                    {
                        return certificate;
                    }
                }
            }

            throw new CertificateNotFoundException($"Find cert error: Target cert '{certificateTitle}' not found in both LocalMachine and CurrentUser store.");
        }

        public string GetCertificateTitle(X509Certificate2 cert)
        {
            return cert.GetCertificateTitle();
        }
    }
}
