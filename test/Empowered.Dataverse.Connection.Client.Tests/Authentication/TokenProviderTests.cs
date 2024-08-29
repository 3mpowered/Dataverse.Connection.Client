using Azure.Core;
using Empowered.Dataverse.Connection.Client.Authentication;
using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using FakeItEasy;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Empowered.Dataverse.Connection.Client.Tests.Authentication;

public class TokenProviderTests
{
    private readonly DataverseClientOptions _dataverseClientOptions;
    private readonly TokenProvider _tokenProvider;
    private readonly IMemoryCache _memoryCache;
    private readonly ICredentialProvider _credentialProvider;

    public TokenProviderTests()
    {
        _dataverseClientOptions = new DataverseClientOptions
        {
            Name = "connection",
            EnvironmentUrl = new Uri("https://test.crm4.dynamics.com"),
            Type = ConnectionType.Unknown
        };
        _memoryCache = A.Fake<IMemoryCache>();
        _credentialProvider = A.Fake<ICredentialProvider>();
        _tokenProvider = new TokenProvider(
            Options.Create(_dataverseClientOptions),
            _memoryCache,
            _credentialProvider,
            NullLogger<TokenProvider>.Instance
        );
    }

    [Fact]
    public async Task ShouldGetTokenFromCache()
    {
        const string expectedToken = "aaaa";
        var scope = $"{_dataverseClientOptions.EnvironmentUrl}.default";
        var cachingKey = $"{_dataverseClientOptions.Type}-{scope}";
        object? accessToken = new AccessToken();
        A.CallTo(() => _memoryCache.TryGetValue(cachingKey, out accessToken))
            .Returns(true)
            .AssignsOutAndRefParameters(new AccessToken(expectedToken, DateTimeOffset.Now));

        var token = await _tokenProvider.GetToken(_dataverseClientOptions.EnvironmentUrl.ToString());

        token.Should().Be(expectedToken);
        A.CallTo(() => _memoryCache.TryGetValue(cachingKey, out accessToken))
            .MustHaveHappenedOnceExactly();
        A.CallTo(() => _credentialProvider.GetCredential()).MustNotHaveHappened();
    }

    [Fact]
    public async Task ShouldGetTokenFromCredential()
    {
        const string expectedToken = "aaaa";
        var scope = $"{_dataverseClientOptions.EnvironmentUrl}.default";
        var cachingKey = $"{_dataverseClientOptions.Type}-{scope}";
        object? accessToken = new AccessToken();
        A.CallTo(() => _memoryCache.TryGetValue(A<object>._, out accessToken))
            .Returns(false);
        var tokenCredential = A.Fake<TokenCredential>();
        A.CallTo(() => _credentialProvider.GetCredential())
            .Returns(tokenCredential);
        A.CallTo(() => tokenCredential.GetTokenAsync(A<TokenRequestContext>._, A<CancellationToken>._))
            .Returns(new AccessToken(expectedToken, DateTimeOffset.Now));

        var token = await _tokenProvider.GetToken(_dataverseClientOptions.EnvironmentUrl.ToString());

        token.Should().Be(expectedToken);
        A.CallTo(() => _memoryCache.TryGetValue(cachingKey, out accessToken))
            .MustHaveHappenedOnceExactly();
        A.CallTo(() => _credentialProvider.GetCredential()).MustHaveHappenedOnceExactly();
        A.CallTo(() => _memoryCache.CreateEntry(A<object>._))
            .MustHaveHappenedOnceExactly();
    }
}