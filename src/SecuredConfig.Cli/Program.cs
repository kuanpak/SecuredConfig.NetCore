using SecuredConfig.Core;
using System.CommandLine;

var fileOption = new Option<FileInfo>(
    aliases: new[] { "--cert", "-c" },
    description: "The certificate file to encrypt the configuration value.")
{
    IsRequired = true
};

var passwordOption = new Option<string?>(
    aliases: new[] { "--password", "-p" },
    description: "The password of the certificate.");

var valueOption = new Option<string>(
    aliases: new[] { "--string", "-s" },
    description: "The string value to be encrypted.")
{
    IsRequired = true
};

var encryptedValueOption = new Option<string>(
    aliases: new[] { "--encrypted-string", "-e" },
    description: "The string value to be decrypted.")
{
    IsRequired = true
};

var encryptCommand = new Command(name: "encrypt", description: "Encrypt the given string by the given certificate.")
{
    fileOption,
    passwordOption,
    valueOption
};

var decryptCommand = new Command(name: "decrypt", description: "Decrypt the given encrypted string by the given PFX certificate.")
{
    fileOption,
    passwordOption,
    encryptedValueOption
};


var rootCommand = new RootCommand("SecuredConfig encryption and decryption tool");
rootCommand.AddCommand(encryptCommand);
rootCommand.AddCommand(decryptCommand);


encryptCommand.SetHandler((file, password, value) =>
    {
        string encrypted = Encrypt(file, password, value);
        Console.WriteLine(encrypted);
    },
    fileOption, passwordOption, valueOption);

decryptCommand.SetHandler((file, password, value) =>
    {
        string decrypted = Decrypt(file, password, value);
        Console.WriteLine(decrypted);
    },
    fileOption, passwordOption, encryptedValueOption);

return await rootCommand.InvokeAsync(args);



static string Encrypt(FileInfo certFile, string? password, string value)
{
    var fileCertProvider = new FileCertificateProvider(certFile.FullName, password);
    CryptoHelper cryptoHelper = new CryptoHelper(fileCertProvider);
    return cryptoHelper.EncryptWithHeader(value, fileCertProvider.Certificate);
}

static string Decrypt(FileInfo certFile, string? password, string value)
{
    var fileCertProvider = new FileCertificateProvider(certFile.FullName, password);
    CryptoHelper cryptoHelper = new CryptoHelper(fileCertProvider);
    return cryptoHelper.DecryptOrBypass(value);
}