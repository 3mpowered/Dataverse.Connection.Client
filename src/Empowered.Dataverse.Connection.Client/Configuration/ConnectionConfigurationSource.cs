using Microsoft.Extensions.Configuration;

namespace Empowered.Dataverse.Connection.Client.Configuration;

public class ConnectionConfigurationSource : IConfigurationSource
{
    private readonly string? _connectionName;

    public ConnectionConfigurationSource(string? connectionName = null)
    {
        _connectionName = connectionName;
    }

    public IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        return new ConnectionConfigurationProvider(_connectionName);
    }
}