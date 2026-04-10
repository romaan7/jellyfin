using System;
using System.Collections.Generic;
using Jellyfin.Plugin.SSO.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.SSO;

/// <summary>
/// SSO Authentication plugin for Jellyfin.
/// </summary>
public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Plugin"/> class.
    /// </summary>
    /// <param name="applicationPaths">The application paths.</param>
    /// <param name="xmlSerializer">The XML serializer.</param>
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    /// <summary>
    /// Gets the current plugin instance.
    /// </summary>
    public static Plugin? Instance { get; private set; }

    /// <inheritdoc/>
    public override Guid Id => new Guid("a1e5c2d3-f4b6-7890-abcd-ef1234567890");

    /// <inheritdoc/>
    public override string Name => "SSO Authentication";

    /// <inheritdoc/>
    public override string Description => "Adds Single Sign-On (SSO) support via OAuth2/OIDC providers like Google.";

    /// <inheritdoc/>
    public IEnumerable<PluginPageInfo> GetPages()
    {
        yield return new PluginPageInfo
        {
            Name = Name,
            EmbeddedResourcePath = GetType().Namespace + ".Configuration.config.html"
        };
    }
}
