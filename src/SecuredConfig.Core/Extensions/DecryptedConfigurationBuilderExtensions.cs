using SecuredConfig.Core;
using SecuredConfig.Core.Overlay;
using System;

namespace Microsoft.Extensions.Configuration
{
    public static class DecryptedConfigurationBuilderExtensions
    {

        /// <summary>
        /// Adds a Overlay Transparent Decryption configuration source to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="configuration">The <see cref="IConfiguration"/> to be chained.</param>
        /// <param name="certificateProvider">The <see cref="ICertificateProvider"/> to use to search the decryption certificate by subject. Default to use <see cref="CertStoreCertificateProvider"/>.</param>
        /// <returns>The <see cref="IConfigurationBuilder"/></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static IConfigurationBuilder AddSecuredConfiguration(this IConfigurationBuilder builder, IConfiguration configuration, ICertificateProvider certificateProvider = null)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            return builder.AddSecuredConfiguration(s =>
            {
                s.Configuration = configuration;
                s.CertificateProvider = certificateProvider;
            });
        }


        /// <summary>
        /// Adds a Overlay Transparent Decryption configuration source to <paramref name="builder"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to add to.</param>
        /// <param name="configureSource">Configures the source.</param>
        /// <returns>The <see cref="IConfigurationBuilder"/>.</returns>
        public static IConfigurationBuilder AddSecuredConfiguration(this IConfigurationBuilder builder, Action<SecuredConfigurationSource> configureSource)
            => builder.Add(configureSource);


    }
}
