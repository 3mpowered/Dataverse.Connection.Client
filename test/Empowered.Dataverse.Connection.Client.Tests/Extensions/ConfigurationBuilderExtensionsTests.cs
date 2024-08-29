using Empowered.Dataverse.Connection.Client.Configuration;
using Empowered.Dataverse.Connection.Client.Extensions;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Empowered.Dataverse.Connection.Client.Tests.Extensions;

public class ConfigurationBuilderExtensionsTests
{
    [Fact]
    public void ShouldAddDataverseConnectionConfigurationSource()
    {
        new ConfigurationBuilder()
            .AddDataverseConnectionSource()
            .Sources
            .OfType<ConnectionConfigurationSource>()
            .Should()
            .ContainSingle();
    }
}