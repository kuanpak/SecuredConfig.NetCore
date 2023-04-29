using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Text.RegularExpressions;

namespace SecuredConfig.Core.Overlay
{
    /// <summary>
    /// Concepts from ChainedConfigurationProvider. Create an overlayed configuration to wrap the given IConfiguration (usually build from ConfigurationBuilder)
    /// and detect whether there is encrypted values then apply auto decryption over the underlying configurations.
    /// https://github.com/dotnet/runtime/blob/main/src/libraries/Microsoft.Extensions.Configuration/src/ChainedConfigurationProvider.cs
    /// </summary>
    public class SecuredConfigurationProvider : ConfigurationProvider
    {
        private readonly IConfiguration _config;

        private bool _tokenRegistered = false;

        private volatile bool isReloading = false;

        /// <summary>
        /// The source settings for this provider.
        /// </summary>
        public SecuredConfigurationSource Source { get; }

        /// <summary>
        /// Initialize a new instance from the source configuration.
        /// </summary>
        /// <param name="source">The source configuration.</param>
        public SecuredConfigurationProvider(SecuredConfigurationSource source)
        {
            _config = source.Configuration;
            Source = source;
        }

        /// <summary>
        /// Attempts to find a value with the given key, returns true if one is found, false otherwise.
        /// </summary>
        /// <param name="key">The key to lookup.</param>
        /// <param name="value">The value found at key if one is found.</param>
        /// <returns>True if key has a value, false otherwise.</returns>
        public override bool TryGet(string key, out string value)
        {
            // wait until the reload complete if it's reloading
            while (isReloading)
            {
                Thread.Sleep(10);
            }
            return base.TryGet(key, out value);
        }

        /// <summary>
        /// Sets a configuration value for the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        public override void Set(string key, string value)
        {
            base.Set(key, value);
            _config[key] = value;
        }

        /// <summary>
        /// Loads configuration values from the source represented by this <see cref="IConfigurationProvider"/>.
        /// </summary>
        public override void Load()
        {
            Load(false);

            if (!_tokenRegistered)
            {
                _config.GetReloadToken().RegisterChangeCallback(state =>
                {
                    Load(reload: true);
                }, this);
                _tokenRegistered = true;
            }
        }

        /// <summary>
        /// Loads configuration values with decrypted string only from origianl configuration sources
        /// </summary>
        /// <param name="reload">True - Triggered by Reload; False - Triggered by initial load.</param>
        private void Load(bool reload)
        {
            try
            {
                if (reload)
                {
                    isReloading = true;
                    Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                }

                var cryptoHelper = new CryptoHelper(Source.CertificateProvider ?? new CertStoreCertificateProvider());  //if not specify ICertificateProvider, default using CertStoreCertificateProvider
                foreach (var kv in _config.AsEnumerable())
                {
                    var decrypted = cryptoHelper.DecryptOrBypass(kv.Value);

                    //only store decrypted values in this provider, non-encrypted values will be referred to the origianl configuration sources.
                    if (decrypted != null && decrypted != kv.Value)
                    {
                        Data[kv.Key] = decrypted;
                    }
                }

            }
            finally
            {
                isReloading = false;
                if (reload)
                {
                    OnReload();  // notify the reload event to the subscribers
                    // subscribe the new downstream reload token, since one reload token can only be triggered once.
                    _config.GetReloadToken().RegisterChangeCallback(state =>
                    {
                        Load(reload: true);
                    }, this);
                }
            }
        }

    }
}
