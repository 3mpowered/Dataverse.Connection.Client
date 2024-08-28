using Empowered.Dataverse.Connection.Client.Configuration;
using Microsoft.Extensions.Configuration;

namespace Empowered.Dataverse.Connection.Client.Extensions;

public static class ConfigurationBuilderExtensions
{
    public static IConfigurationBuilder AddDataverseConnectionSource(this IConfigurationBuilder builder, string? connectionName = null) =>
        builder.Add(new ConnectionConfigurationSource(connectionName));
}