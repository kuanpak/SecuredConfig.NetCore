using Microsoft.Extensions.Configuration;
using SecuredConfig.Core;
using SecuredConfig.Core.Overlay;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.Hosting
{
    public static class DecryptedConfigurationHostBuilderExtensions
    {
        /// <summary>
        /// Apply an Overlayed Decrypted Configuration <see cref="SecuredConfigurationSource"/> over the original target Configuration.
        /// </summary>
        /// <param name="builder">The <see cref="IHostBuilder"/> to apply to.</param>
        /// <param name="certificateProvider">The <see cref="ICertificateProvider"/> to use to search the decryption certificate by subject. Default to use <see cref="CertStoreCertificateProvider"/>.</param>
        /// <returns>The <see cref="IHostBuilder"/></returns>
        public static IHostBuilder UseSecuredConfiguration(this IHostBuilder builder, ICertificateProvider certificateProvider = null)
        {
            builder.ConfigureAppConfiguration((context, config) =>
            {
                //create a new ConfigurationBuilder to copy the original sources
                var newbuilder = new ConfigurationBuilder();
                foreach (var source in config.Sources)
                {
                    newbuilder.Add(source);
                }
                //cannot use config.Build() directly as it will return the same ConfigurationManager/Builder instance in .NET 6 and will cause Stackoverflow in later use
                var targetConfig = newbuilder.Build();


                config.AddSecuredConfiguration(targetConfig, certificateProvider); //add a overlayed source on the original target configuration
            });
            return builder;
        }
    }
}
