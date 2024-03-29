﻿using Yarp.ReverseProxy.Configuration;

namespace application_gateway_lab.Infrastructure;

/// <summary>
/// Gateway 設定
/// </summary>
public record GatewayConfig
{
    public GatewayConfig(IProxyConfig getConfig)
    {
        this.Routes = getConfig.Routes;
        this.Clusters = getConfig.Clusters;
    }

    public string ProxyHost { get; } = Environment.GetEnvironmentVariable("MACHINENAME") ?? Environment.MachineName;
    public IReadOnlyList<RouteConfig> Routes { get; }
    public IReadOnlyList<ClusterConfig> Clusters { get; }
}