using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Extensions;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.PowerPlatform.Dataverse.Client;
using Microsoft.PowerPlatform.Dataverse.Client.Utils;
using Xunit;

namespace Empowered.Dataverse.Connection.Client.Tests.Extensions;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void ShouldInstanciateDataverseClientFactory()
    {
        var serviceCollection = new ServiceCollection()
            .AddDataverseClientFactory();
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var dataverseClientFactory = serviceProvider.GetRequiredService<IDataverseClientFactory>();

        dataverseClientFactory.Should().NotBeNull();
    }

    [Fact]
    // An exception is thrown because I don't want to provide a valid service client connection.
    public void ShouldTryInstanciateServiceClient()
    {
        var configuration = new ConfigurationBuilder()
            .Build();
        var serviceCollection = new ServiceCollection()
            .AddSingleton<IConfiguration>(configuration)
            .AddDataverseClient<ServiceClient>();
        var serviceProvider = serviceCollection.BuildServiceProvider();

        var action = () => serviceProvider.GetRequiredService<ServiceClient>();

        action.Should()
            .ThrowExactly<DataverseConnectionException>();
    }
}