using System.Security.Cryptography;
using Azure.Identity;
using Empowered.Dataverse.Connection.Client.Authentication;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Empowered.Dataverse.Connection.Client.Tests.Authentication;

public class CredentialProviderTests
{
    [Theory]
    [InlineData(ConnectionType.UserPassword, typeof(UsernamePasswordCredential))]
    [InlineData(ConnectionType.ClientSecret, typeof(ClientSecretCredential))]
    [InlineData(ConnectionType.AzureDefault, typeof(DefaultAzureCredential))]
    [InlineData(ConnectionType.AzurePowershell, typeof(AzurePowerShellCredential))]
    [InlineData(ConnectionType.Interactive, typeof(InteractiveBrowserCredential))]
    [InlineData(ConnectionType.Unknown, typeof(InteractiveBrowserCredential))]
    [InlineData(ConnectionType.AzureCli, typeof(AzureCliCredential))]
    [InlineData(ConnectionType.AzureDeveloperCli, typeof(AzureDeveloperCliCredential))]
    [InlineData(ConnectionType.DeviceCode, typeof(DeviceCodeCredential))]
    [InlineData(ConnectionType.ManagedIdentity, typeof(ManagedIdentityCredential))]
    [InlineData(ConnectionType.VisualStudioCode, typeof(VisualStudioCodeCredential))]
    [InlineData(ConnectionType.VisualStudio, typeof(VisualStudioCredential))]
    public void ShouldGetSufficientCredentialForConnectionType(ConnectionType connectionType,Type credentialType)
    {
        var options = new DataverseClientOptions
        {
            Name = "some name",
            EnvironmentUrl = new Uri("https://test.crm4.dynamics.com"),
            Type = connectionType,
            ApplicationId = Guid.NewGuid().ToString(),
            TenantId = Guid.NewGuid().ToString(),
            Password = "secret",
            CertificatePassword = "secret",
            ClientSecret = "secret",
            UserName = "a@b.de",
            CertificateFilePath = "C:\\TEMP"
        };

        var credentialProvider = new CredentialProvider(Options.Create(options));

        var tokenCredential = credentialProvider.GetCredential();

        tokenCredential.Should().BeOfType(credentialType);
    }

    [Fact(Skip = "doesn't work on macos")]
    // I don't want to test with a real certificate here
    public void ShouldThrowOnGettingClientCertificate()
    {
        var options = new DataverseClientOptions
        {
            Name = "some name",
            EnvironmentUrl = new Uri("https://test.crm4.dynamics.com"),
            Type = ConnectionType.ClientCertificate,
            ApplicationId = Guid.NewGuid().ToString(),
            TenantId = Guid.NewGuid().ToString(),
            Password = "secret",
            CertificatePassword = "secret",
            ClientSecret = "secret",
            UserName = "a@b.de",
            CertificateFilePath = "C:\\TEMP"
        };

        var credentialProvider = new CredentialProvider(options);

        var action = () => credentialProvider.GetCredential();

        action.Should().Throw<CryptographicException>();
    }
}
