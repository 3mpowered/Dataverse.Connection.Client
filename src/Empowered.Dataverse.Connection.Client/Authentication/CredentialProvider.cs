using System.Security.Cryptography.X509Certificates;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Empowered.Dataverse.Connection.Client.Constants;
using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using Microsoft.Extensions.Options;

namespace Empowered.Dataverse.Connection.Client.Authentication;

public class CredentialProvider(DataverseClientOptions options) : ICredentialProvider
{
    public CredentialProvider(IOptions<DataverseClientOptions> options) : this(options.Value)
    {
    }

    public TokenCredential GetCredential()
    {
        return options.Type switch
        {
            ConnectionType.UserPassword => new UsernamePasswordCredential(
                options.UserName,
                options.Password,
                options.TenantId,
                ConnectionDefaults.DefaultAppId
            ),
            ConnectionType.ClientCertificate => new ClientCertificateCredential(
                options.TenantId,
                options.ApplicationId,
                new X509Certificate2(options.CertificateFilePath!, options.CertificatePassword)
            ),
            ConnectionType.ClientSecret => new ClientSecretCredential(
                options.TenantId,
                options.ApplicationId,
                options.ClientSecret
            ),
            ConnectionType.Interactive => new InteractiveBrowserCredential(),
            ConnectionType.Unknown => new InteractiveBrowserCredential(),
            ConnectionType.DeviceCode => new DeviceCodeCredential(new DeviceCodeCredentialOptions
            {
                TokenCachePersistenceOptions = new TokenCachePersistenceOptions
                {
                    Name = $"{options.Name}_{options.Type}"
                },
                DisableAutomaticAuthentication = false,
                DisableInstanceDiscovery = false,
                RetryPolicy = new RetryPolicy(1),
            }),
            ConnectionType.ManagedIdentity => GetManagedIdentityCredential(),
            ConnectionType.AzureDefault => !string.IsNullOrWhiteSpace(options.ApplicationId)
                ? new DefaultAzureCredential(new DefaultAzureCredentialOptions
                    {
                        ManagedIdentityClientId = options.ApplicationId
                    }
                )
                : new DefaultAzureCredential(),
            ConnectionType.AzureCli => new AzureCliCredential(),
            ConnectionType.AzureDeveloperCli => new AzureDeveloperCliCredential(),
            ConnectionType.AzurePowershell => new AzurePowerShellCredential(),
            ConnectionType.VisualStudio => new VisualStudioCredential(),
            ConnectionType.VisualStudioCode => new VisualStudioCodeCredential(),
            _ => throw new ArgumentOutOfRangeException($"Unknown connection type {options.Type}")
        };
    }

    private ManagedIdentityCredential GetManagedIdentityCredential()
    {
        // TODO: Implement resource identifier
        return new ManagedIdentityCredential(options.ApplicationId);
    }
}