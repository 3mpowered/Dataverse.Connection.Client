using Azure.Core;
using Empowered.Dataverse.Connection.Client.Contracts;
using Empowered.Dataverse.Connection.Client.Settings;
using Empowered.Dataverse.Connection.Store.Contracts;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Empowered.Dataverse.Connection.Client.Authentication;

public class TokenProvider(
    DataverseClientOptions options,
    IMemoryCache cache,
    ICredentialProvider credentialProvider,
    ILogger<TokenProvider> logger)
    : ITokenProvider
{
    public static readonly TimeSpan CacheTreshold = TimeSpan.FromMinutes(5);

    public TokenProvider(
        IOptions<DataverseClientOptions> options, 
        IMemoryCache cache, 
        ICredentialProvider credentialProvider,
        ILogger<TokenProvider> logger) : this(options.Value, cache, credentialProvider, logger)
    {
    }

    public async Task<string> GetToken(string environmentUri)
    {
        var instanceUrl = new Uri(environmentUri);
        var scope = $"{instanceUrl.Scheme}://{instanceUrl.Authority}/.default";
        logger.LogTrace("Retrieving token for environment {InstanceUrl} with scope {Scope}", environmentUri, scope);

        object key = $"{options.Type}-{scope}";
        if (cache.TryGetValue<AccessToken>(key, out var token))
        {
            logger.LogTrace("Getting cached token expiring {ExpirationDate}", token.ExpiresOn);
            return token.Token;
        }

        var credential = credentialProvider.GetCredential();
        logger.LogTrace("Authenticating with credential {CredentialType} for connection type {ConnectionType}", credential.GetType(),
            options.Type);

        token = await credential.GetTokenAsync(new TokenRequestContext(new[] { scope }), new CancellationToken());
        var cacheExpirationDate = token.ExpiresOn - CacheTreshold;
        cache.Set(key, token, cacheExpirationDate);
        logger.LogTrace("Caching token with expiration date {ExpirationDate} until {CacheExpiration}", token.ExpiresOn, cacheExpirationDate);

        return token.Token;
    }
}