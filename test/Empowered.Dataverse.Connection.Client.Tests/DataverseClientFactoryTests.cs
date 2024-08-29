using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Extensions;
using Empowered.Dataverse.Connection.Store.Contracts;
using Empowered.Dataverse.Connection.Store.Model;
using FakeItEasy;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.PowerPlatform.Dataverse.Client;
using Microsoft.PowerPlatform.Dataverse.Client.Utils;
using Microsoft.Xrm.Sdk;
using Xunit;

namespace Empowered.Dataverse.Connection.Client.Tests;

public class DataverseClientFactoryTests
{
    private readonly IConnectionStore _connectionStore;
    private readonly IDataverseClientFactory _dataverseClientFactory;

    public DataverseClientFactoryTests()
    {
        _connectionStore = A.Fake<IConnectionStore>();
        var serviceProvider = new ServiceCollection()
            .AddDataverseClientFactory()
            .AddSingleton<IConnectionStore>(_ => _connectionStore)
            .BuildServiceProvider();

        _dataverseClientFactory = serviceProvider.GetRequiredService<IDataverseClientFactory>();
    }

    [Fact]
    // I dont want to provide a valid configuration in test
    public void ShouldTryGetServiceClient()
    {
        const string name = "connection";
        var interactiveConnection = DataverseConnection.ClientSecretConnection(
            name,
            new Uri("https://test.crm4.dynamics.com"),
            Guid.NewGuid().ToString(),
            Guid.NewGuid().ToString(),
            "secret"
        );

        A.CallTo(() => _connectionStore.Get(name)).Returns(interactiveConnection);

        var action = () => _dataverseClientFactory.Get<ServiceClient>(name);

        action.Should().ThrowExactly<DataverseConnectionException>();
    }
}