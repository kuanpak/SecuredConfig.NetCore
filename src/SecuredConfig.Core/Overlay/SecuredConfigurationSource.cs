using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecuredConfig.Core.Overlay
{
    public class SecuredConfigurationSource : IConfigurationSource
    {
        public ICertificateProvider CertificateProvider { get; set; }

        public IConfiguration Configuration { get; set; }


        public IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            return new SecuredConfigurationProvider(this);
        }
    }
}
