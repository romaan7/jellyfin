using Jellyfin.Plugin.SSO.Discovery;
using Jellyfin.Plugin.SSO.Providers;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Plugins;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.SSO;

/// <summary>
/// Registers the SSO plugin's services with the dependency injection container.
/// </summary>
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc/>
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<OidcDiscoveryService>();
        serviceCollection.AddSingleton<IExternalAuthenticationProvider, GoogleOAuthProvider>();
        serviceCollection.AddSingleton<IExternalAuthenticationProvider, GenericOIDCProvider>();
        serviceCollection.AddHttpClient();
    }
}
