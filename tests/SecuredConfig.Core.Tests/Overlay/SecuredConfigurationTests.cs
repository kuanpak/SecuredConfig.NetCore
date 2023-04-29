using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SecuredConfig.Core.Tests.Options;
using Xunit;

namespace SecuredConfig.Core.Tests.Overlay
{
    public class SecuredConfigurationTests
    {


        [Fact]
        public void AddSecuredConfiguration_With_Nested_Unencrypted_values()
        {
            var builder = new ConfigurationBuilder();
            builder.AddInMemoryCollection(new[]
            {
                new KeyValuePair<string, string>("testkey1", "testvalue1"),
                new KeyValuePair<string, string>("testkey2", "testvalue2"),
                new KeyValuePair<string, string>("parent:child1", "childvalue1"),
                new KeyValuePair<string, string>("parent:child2", "childvalue2")
            });
            var configuration = builder.Build();
            var parent = new Parent();
            //configuration.GetSection("parent").GetChildren().ToList().Should().HaveCount(2);


            //Act: build the overlay configuration
            var overlayConfig = builder.AddSecuredConfiguration(configuration).Build();

            overlayConfig["testkey1"].Should().Be("testvalue1");
            overlayConfig["testkey2"].Should().Be("testvalue2");
            overlayConfig.GetSection("parent")["child1"].Should().Be("childvalue1");
            overlayConfig.GetSection("parent").Bind(parent);
            parent.Child2.Should().Be("childvalue2");
        }

        [Fact]
        public void SecuredConfigurationProvider_Can_Set_ConfigurationValue()
        {
            var builder = new ConfigurationBuilder();
            builder.AddInMemoryCollection(new[]
            {
                new KeyValuePair<string, string>("testkey1", "testvalue1"),
                new KeyValuePair<string, string>("testkey2", "testvalue2"),
                new KeyValuePair<string, string>("parent:child1", "childvalue1"),
                new KeyValuePair<string, string>("parent:child2", "childvalue2")
            });
            var configuration = builder.Build();
            var parent = new Parent();
            //configuration.GetSection("parent").GetChildren().ToList().Should().HaveCount(2);


            //Act: build the overlay configuration
            var overlayConfig = builder.AddSecuredConfiguration(configuration).Build();

            overlayConfig["testkey1"].Should().Be("testvalue1");
            overlayConfig["testkey2"].Should().Be("testvalue2");
            overlayConfig.GetSection("parent")["child1"].Should().Be("childvalue1");
            overlayConfig.GetSection("parent").Bind(parent);
            parent.Child2.Should().Be("childvalue2");

            overlayConfig["parent:child2"] = "updated";
            overlayConfig.GetSection("parent")["child2"].Should().Be("updated");
        }


        [Fact]
        public void AddSecuredConfiguration_with_EncryptedValues()
        {
            var json = @"
{
    ""firstname"": ""test"",
    ""ConnectionStrings"": {
        ""Default"": ""Data Source=(local);Initial Catalog=Test;Password={Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==};User ID=dev;MultipleActiveResultSets=true"",
    },
    ""residential.address"": {
        ""street.name"": ""Something street"",
        ""zipcode"": ""12345""
    }
}";

            var builder = new ConfigurationBuilder();
            var config = builder.AddJsonFile(provider: TestStreamHelpers.StringToFileProvider(json),
                                                                path: TestStreamHelpers.ArbitraryFilePath,
                                                                optional: true,
                                                                reloadOnChange: false)
                .Build();

            //Act: build the overlay configuration
            var overlayConfig = builder.AddSecuredConfiguration(config, MockHelpers.GetDummyCertificateProvider()).Build();


            overlayConfig["firstname"].Should().Be("test");
            overlayConfig.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");
            overlayConfig["residential.address:street.name"].Should().Be("Something street");
            overlayConfig["nonExisting"].Should().BeNull();
        }

        
        [Fact]
        public async Task ReloadConfigurationWhenFileChanged()
        {
            string dummyEncrypted = "{Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==}";
            var json = @"
{
    ""firstname"": ""test"",
    ""ConnectionStrings"": {
        ""Default"": ""Data Source=(local);Initial Catalog=Test;Password={Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==};User ID=dev;MultipleActiveResultSets=true"",
    },
    ""residential.address"": {
        ""street.name"": ""Something street"",
        ""zipcode"": ""12345""
    }
}";

            string filepath = "test.json";
            File.WriteAllText(filepath, json);

            var builder = new ConfigurationBuilder();
            var config = builder.AddJsonFile(path: filepath, optional: true, reloadOnChange: true).Build();
            var dummyCertProvider = MockHelpers.GetDummyCertificateProvider();
            var dummyCert = dummyCertProvider.GetCertificate("CN=dummy,NotAfter=2033-04-25");

            //Act: build the overlay configuration
            var overlayConfig = builder.AddSecuredConfiguration(config, dummyCertProvider).Build();
            var token = overlayConfig.GetReloadToken();

            ManualResetEventSlim changedEvent = new ManualResetEventSlim(false);
            token.RegisterChangeCallback(o =>
            {
                changedEvent.Set();
            }, token);


            overlayConfig["firstname"].Should().Be("test");
            overlayConfig.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");
            overlayConfig["residential.address:street.name"].Should().Be("Something street");
            overlayConfig["residential.address:zipcode"].Should().Be("12345");
            overlayConfig["nonExisting"].Should().BeNull();

            //try to update the file to trigger reload
            CryptoHelper cryptoHelper = new CryptoHelper(dummyCertProvider);
            string encrypted2 = cryptoHelper.EncryptWithHeader("plainValue2", dummyCert);

            File.WriteAllText(filepath, json.Replace("12345", "56789").Replace(dummyEncrypted, encrypted2));
            changedEvent.Wait(5000);
            overlayConfig["residential.address:zipcode"].Should().Be("56789", because: "The value should be modified in json file");
            await Task.Delay(800);  // delay a bit more to wait for Overlay provider finish reload the decrypted values

            overlayConfig.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue2;User ID=dev;MultipleActiveResultSets=true",
                because: "The connection string should be replaced by the new encrypted string in json file");
        }

        [Fact]
        public async Task OptionMonitor_ShouldReloadConfig_WhenFileChanged()
        {
            // Arrange
            string dummyEncrypted = "{Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==}";
            var json = @"
{
    ""firstname"": ""test"",
    ""ConnectionStrings"": {
        ""Default"": ""Data Source=(local);Initial Catalog=Test;Password={Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==};User ID=dev;MultipleActiveResultSets=true"",
    },
    ""residential.address"": {
        ""street.name"": ""Something street"",
        ""zipcode"": ""12345""
    }
}";

            string filepath = "monitortest.json";
            File.WriteAllText(filepath, json);
            var dummyCertProvider = MockHelpers.GetDummyCertificateProvider();
            var dummyCert = dummyCertProvider.GetCertificate("CN=dummy,NotAfter=2033-04-25");

            // Act: create host with overlay config
            var host = Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration(builder =>
                {
                    builder.AddJsonFile(filepath, true, true);
                })
                .UseSecuredConfiguration(dummyCertProvider)
                .ConfigureServices((context, services) =>
                {
                    services.Configure<ConnectionStrings>(context.Configuration.GetSection("ConnectionStrings"));
                })
                .Build();

            var config = host.Services.GetService<IConfiguration>();

            var optMon = host.Services.GetRequiredService<IOptionsMonitor<ConnectionStrings>>();
            var conns = optMon.CurrentValue;

            ManualResetEventSlim changedEvent = new ManualResetEventSlim(false);
            optMon.OnChange((opt, name) =>
            {
                conns.Default = opt.Default;
                changedEvent.Set();
            });

            conns.Default.Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");

            config["firstname"].Should().Be("test");
            config.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");
            config["residential.address:street.name"].Should().Be("Something street");
            config["residential.address:zipcode"].Should().Be("12345");
            config["nonExisting"].Should().BeNull();

            CryptoHelper cryptoHelper = new CryptoHelper(dummyCertProvider);
            string encrypted2 = cryptoHelper.EncryptWithHeader("plainValue2", dummyCert);

            //try to update the file to trigger reload
            File.WriteAllText(filepath, json.Replace("12345", "56789").Replace(dummyEncrypted, encrypted2));
            changedEvent.Wait(5000);
            config["residential.address:zipcode"].Should().Be("56789", because: "The value should be modified in json file");
            string expected = "Data Source=(local);Initial Catalog=Test;Password=plainValue2;User ID=dev;MultipleActiveResultSets=true";
            var sw = Stopwatch.StartNew();
            long totalDelay = 0;
            //wait until the config value updated
            while (conns.Default != expected && sw.ElapsedMilliseconds < 30000)
            {
                totalDelay += 10;
                await Task.Delay(10);  // delay a bit more to wait for Overlay provider finish reload the decrypted values
            }
            long elapsedMs = sw.ElapsedMilliseconds;
            conns.Default.Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue2;User ID=dev;MultipleActiveResultSets=true",
                because: "The connection string should be replaced by the new encrypted string in json file");
            elapsedMs.Should().BeLessThan(5000);

            // replace the json again
            string encrypted3 = cryptoHelper.EncryptWithHeader("plainValue3", dummyCert);
            File.WriteAllText(filepath, json.Replace(dummyEncrypted, encrypted3));
            string expected3 = "Data Source=(local);Initial Catalog=Test;Password=plainValue3;User ID=dev;MultipleActiveResultSets=true";
            sw.Restart();
            totalDelay = 0;
            //wait until the config value updated
            while (conns.Default != expected3 && sw.ElapsedMilliseconds < 30000)
            {
                totalDelay += 10;
                await Task.Delay(10);  // delay a bit more to wait for Overlay provider finish reload the decrypted values
            }
            elapsedMs = sw.ElapsedMilliseconds;
            conns.Default.Should().Be(expected3, because: "The connection string should be updated on every file change");
            elapsedMs.Should().BeLessThan(5000);

        }
        

        [Fact]
        public void HostBuilderUseSecuredConfiguration_dummy_encrypted()
        {
            var json = @"
{
    ""firstname"": ""test"",
    ""ConnectionStrings"": {
        ""Default"": ""Data Source=(local);Initial Catalog=Test;Password={Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==};User ID=dev;MultipleActiveResultSets=true"",
    },
    ""residential.address"": {
        ""street.name"": ""Something street"",
        ""zipcode"": ""12345""
    }
}";
            string filepath = "hosttest.json";
            File.WriteAllText(filepath, json);

            var host = Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration(builder =>
                {
                    builder.AddJsonFile(filepath, true, true);
                })
                .UseSecuredConfiguration(MockHelpers.GetDummyCertificateProvider())
                .Build();

            var config = host.Services.GetService<IConfiguration>();
            config.Should().NotBeNull();

            config.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");

        }


        [Fact]
        public void HostBuilderUseSecuredConfiguration_mockcert_encrypted()
        {
            var certificateProvider = MockHelpers.GetMockCertificateProvider();
            CryptoHelper cryptoHelper = new CryptoHelper(certificateProvider);
            var cert = certificateProvider.GetCertificate("CN=unittest-mock");

            string plainText = "plainValue1";
            string encrypted = cryptoHelper.EncryptWithHeader(plainText, cert);

            var json = @"
{
    ""firstname"": ""test"",
    ""ConnectionStrings"": {
        ""Default"": ""Data Source=(local);Initial Catalog=Test;Password="+encrypted+@";User ID=dev;MultipleActiveResultSets=true"",
    },
    ""residential.address"": {
        ""street.name"": ""Something street"",
        ""zipcode"": ""12345""
    }
}";
            string filepath = "hosttest.json";
            File.WriteAllText(filepath, json);

            var host = Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration(builder =>
                {
                    builder.AddJsonFile(filepath, true, true);
                })
                .UseSecuredConfiguration(certificateProvider)
                .Build();

            var config = host.Services.GetService<IConfiguration>();
            config.Should().NotBeNull();

            config.GetConnectionString("Default").Should().Be("Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;MultipleActiveResultSets=true");

        }

    }


    public class Parent
    {
        public string Child1 { get; set; }
        public string Child2 { get; set; }
    }
}
