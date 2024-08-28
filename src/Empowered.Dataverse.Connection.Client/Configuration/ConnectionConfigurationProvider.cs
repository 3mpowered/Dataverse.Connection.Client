using System.Reflection;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using Empowered.Dataverse.Connection.Store.Factories;
using Microsoft.Extensions.Configuration;

namespace Empowered.Dataverse.Connection.Client.Configuration;

public class ConnectionConfigurationProvider : ConfigurationProvider
{
    private readonly string? _connectionName;
    private readonly IConnectionStore _connectionStore;

    public ConnectionConfigurationProvider(string? connectionName)
    {
        _connectionName = connectionName;
        _connectionStore = ConnectionStoreFactory.Get();
    }

    public override void Load()
    {
        var connection = string.IsNullOrWhiteSpace(_connectionName)
            ? _connectionStore.GetActive()
            : _connectionStore.Get(_connectionName);

        var options = new DataverseClientOptions(connection);

        var optionProperties = options
            .GetType()
            .GetProperties(BindingFlags.Public | BindingFlags.Instance);
        
        foreach (var propertyInfo in optionProperties)
        {
            var key = $"{DataverseClientOptions.Section}:{propertyInfo.Name}";
            var value = propertyInfo.GetValue(options)?.ToString();
            Data.Add(key, value);
        }

        base.Load();
    }
}