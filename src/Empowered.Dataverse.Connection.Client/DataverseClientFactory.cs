using Empowered.Dataverse.Connection.Client.Authentication;
using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Xrm.Sdk;

namespace Empowered.Dataverse.Connection.Client;

public class DataverseClientFactory : IDataverseClientFactory
{
    private readonly IConnectionStore _connectionStore;
    private readonly IServiceProvider _serviceProvider;

    public DataverseClientFactory(IConnectionStore connectionStore, IServiceProvider serviceProvider)
    {
        _connectionStore = connectionStore;
        _serviceProvider = serviceProvider;
    }

    public TClient Get<TClient>(string? name) where TClient : class, IOrganizationService
    {
        var memoryCache = _serviceProvider.GetRequiredService<IMemoryCache>();
        var tokenProviderLogger = _serviceProvider.GetRequiredService<ILogger<TokenProvider>>();
        var connection = string.IsNullOrWhiteSpace(name) ? _connectionStore.GetActive() : _connectionStore.Get(name);
        var clientOptions = new DataverseClientOptions(connection);
        var credentialProvider = new CredentialProvider(clientOptions);
        var tokenProvider = new TokenProvider(clientOptions, memoryCache, credentialProvider, tokenProviderLogger);
        var serviceClientLogger = _serviceProvider.GetRequiredService<ILogger<EmpoweredServiceClient>>();

        return new EmpoweredServiceClient(tokenProvider, connection.EnvironmentUrl, serviceClientLogger) as TClient ??
               throw new InvalidCastException($"Client type {typeof(TClient).Name} is invalid.");
    }
}