using System.Net.Http.Headers;
using System.Reflection;
using application_gateway_lab.Infrastructure.Options;
using application_gateway_lab.Infrastructure.TicketStore;
using HealthChecks.Prometheus.Metrics;
using HealthChecks.UI.Client;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

builder.Host
       .UseSerilog((context, configuration) =>
       {
           configuration.ReadFrom.Configuration(context.Configuration);
           configuration.Enrich.WithProperty("ApplicationName", AppDomain.CurrentDomain.FriendlyName);
           configuration.Enrich.WithProperty("MACHINENAME",
                                             Environment.GetEnvironmentVariable("MACHINENAME") ??
                                             Environment.MachineName);
       })
       .ConfigureAppConfiguration(o =>
       {
           o.AddJsonFile("ReverseProxy-ClustersSetting.json", true, true);
           o.AddJsonFile("ReverseProxy-RoutesSetting.json", true, true);
       });

var authOptions = AuthOptions.CreateInstance(builder.Configuration);

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

builder.Services.AddHealthChecks();

builder.Services.AddW3CLogging(logging =>
{
    // Log all W3C fields
    logging.LoggingFields = W3CLoggingFields.All;

    logging.FileSizeLimit = 5 * 1024 * 1024;
    logging.RetainedFileCountLimit = 2;
    logging.FileName = AppDomain.CurrentDomain.FriendlyName + Environment.MachineName;
    logging.FlushInterval = TimeSpan.FromSeconds(2);

    //.net 7 new feature
    logging.AdditionalRequestHeaders.Add("x-forwarded-for");
});

var redisUrl = builder.Configuration.GetValue<string>("RedisUrl");

//OAuth
builder.Services.AddAuthentication(options =>
       {
           options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
           options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;

           options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
           options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
           options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
           options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
       })
       .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
       {
           options.Cookie.Name = "sample_signin";
           options.Cookie.SameSite = SameSiteMode.None;

           options.SessionStore = new RedisCacheTicketStore(new RedisCacheOptions { Configuration = redisUrl });

           options.Events = new CookieAuthenticationEvents
           {
               OnValidatePrincipal = async cookieContext =>
               {
                   Console.WriteLine("CookieAuthenticationEvents - OnValidatePrincipal");

                   /*
                    * cookieContext.Properties.GetTokenValue(key)
                    * cookieContext.Properties.UpdateTokenValue(key)
                    * key ????????????????????????
                    * 1. access_token
                    * 2. id_token       = openId connection ????????????????????? token????????? 5 ????????????
                    * 3. refresh_token
                    * 4. token_type
                    * 5. expires_at     = access_token ????????????
                    *
                    * cookieContext.Properties.IssuedUtc = ??? OAuth Server ?????????????????????
                    * 
                    * cookieContext.Properties.ExpiresUtc
                    *   * cookies ??????????????????
                    *   * ?????? AddOpenIdConnect ??????????????? UseTokenLifeTime ?????????????????????????????? id_token ???????????????
                    */

                   var now = DateTimeOffset.UtcNow;
                   var expiresAt = cookieContext.Properties.GetTokenValue("expires_at");
                   var accessTokenExpiration = DateTimeOffset.Parse(expiresAt);

                   var timeRemaining = accessTokenExpiration.Subtract(now);

                   // TODO: Get this from configuration with a fallback value.
                   var refreshThresholdMinutes = 5;
                   var refreshThreshold = TimeSpan.FromMinutes(refreshThresholdMinutes);

                   if (timeRemaining < refreshThreshold)
                   {
                       Console.WriteLine("CookieAuthenticationEvents - OnValidatePrincipal - refresh");

                       var refreshToken = cookieContext.Properties.GetTokenValue("refresh_token");

                       // TODO: Get this HttpClient from a factory
                       var response = await new HttpClient().RequestRefreshTokenAsync(
                                          new RefreshTokenRequest
                                          {
                                              Address = $"{authOptions.Authority}/connect/token",
                                              ClientId = authOptions.ClientId,
                                              ClientSecret = authOptions.ClientSecret,
                                              RefreshToken = refreshToken
                                          });

                       if (!response.IsError)
                       {
                           var expiresInSeconds = response.ExpiresIn;
                           var updatedExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds);

                           cookieContext.Properties.UpdateTokenValue("expires_at", updatedExpiresAt.ToString());

                           cookieContext.Properties.UpdateTokenValue("access_token", response.AccessToken);
                           cookieContext.Properties.UpdateTokenValue("refresh_token", response.RefreshToken);
                           cookieContext.Properties.UpdateTokenValue("id_token", response.IdentityToken);

                           // Indicate to the cookie middleware that the cookie should be
                           // remade (since we have updated it)
                           cookieContext.ShouldRenew = true;
                       }
                       else
                       {
                           cookieContext.RejectPrincipal();
                           await cookieContext.HttpContext.SignOutAsync();
                       }
                   }
               }
           };
       })
       .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
       {
           options.Authority = authOptions.Authority;
           options.ClientId = authOptions.ClientId;
           options.ClientSecret = authOptions.ClientSecret;

           // ???????????? redirect url ?????????????????????
           // options.CallbackPath = "/auth-redirect-url";

           options.RequireHttpsMetadata = false;
           options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
           // options.ResponseMode = OpenIdConnectResponseMode.FormPost;

           // ??????????????????????????? scope ??????????????? profile ?????????
           options.Scope.Clear();

           //?????? .net ????????? openid ???????????????????????? Scope
           options.Scope.Add(OpenIdConnectScope.OpenId);

           // ????????????????????? OAuth Scope
           foreach (var item in authOptions.WebApiAudience)
           {
               options.Scope.Add(item);
           }

           // ?????? scope ?????? Auth Server ?????? Refresh Token
           options.Scope.Add(OpenIdConnectScope.OfflineAccess);

           // if true , cookies ExpiresUtc will be use id_token expires time
           // options.UseTokenLifetime = true;

           options.SaveTokens = true;
           options.GetClaimsFromUserInfoEndpoint = true;

           options.TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" };

           // OpenIdConnect ???????????? PKCE = True ??????????????????
           // options.UsePkce = false; 
       });

//??????????????????????????? Redis ????????????
//????????????????????????????????????????????????????????????????????????
//REF: https://docs.microsoft.com/en-us/aspnet/core/security/cookie-sharing?view=aspnetcore-6.0#share-authentication-cookies-among-aspnet-core-apps
//REF: https://docs.microsoft.com/zh-tw/aspnet/core/security/data-protection/implementation/key-storage-providers?view=aspnetcore-6.0&tabs=visual-studio#redis
builder.Services
       .AddDataProtection()
       .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(redisUrl), "LoginKey:")
       .SetApplicationName("Sample");

// Add the reverse proxy capability to the server
builder.Services
       .AddReverseProxy()
       .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
       .AddTransforms(context =>
       {
           context.AddRequestTransform(async transformContext =>
           {
               // ??? openId ???????????? Bearer Token ?????? Header
               var tokenAsync = await transformContext.HttpContext.GetTokenAsync("access_token");
               transformContext.ProxyRequest.Headers.Authorization =
                   new AuthenticationHeaderValue("Bearer", tokenAsync);
           });
       });

builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto |
                               ForwardedHeaders.XForwardedHost;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders =
        ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseHealthChecks(
       "/metrics",
       new HealthCheckOptions
       {
           ResponseWriter = PrometheusResponseWriter.WritePrometheusResultText, AllowCachingResponses = false
       })
   .UseHealthChecks(
       "/health",
       new HealthCheckOptions
       {
           ResultStatusCodes =
           {
               [HealthStatus.Healthy] = StatusCodes.Status200OK,
               [HealthStatus.Degraded] = StatusCodes.Status200OK,
               [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable
           },
           AllowCachingResponses = false,
           Predicate = _ => true,
           ResponseWriter = UIResponseWriter.WriteHealthCheckUIResponse
       });

// ?????? favicon.ico ?????????????????? Proxy ??? Route ??????????????????????????????????????????????????????
app.Map("/favicon.ico", () => "");

app.UseW3CLogging();

app.UseRouting();

app.UseCors("CorsPolicy");

app.UseAuthentication();

app.UseAuthorization();

app.MapReverseProxy();

app.Run();