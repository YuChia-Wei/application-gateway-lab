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
                    * key 可使用的參數值有
                    * 1. access_token
                    * 2. id_token       = openId connection 驗證身分所需的 token，預設 5 分鐘過期
                    * 3. refresh_token
                    * 4. token_type
                    * 5. expires_at     = access_token 的到期日
                    *
                    * cookieContext.Properties.IssuedUtc = 跟 OAuth Server 進行驗證的時間
                    * 
                    * cookieContext.Properties.ExpiresUtc
                    *   * cookies 有效期的時間
                    *   * 如果 AddOpenIdConnect 裡面有設定 UseTokenLifeTime 的話，這個時間會使用 id_token 的過期時間
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

           // 如果要改 redirect url 的時候要用這個
           // options.CallbackPath = "/auth-redirect-url";

           options.RequireHttpsMetadata = false;
           options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
           // options.ResponseMode = OpenIdConnectResponseMode.FormPost;

           // 沒有清除的話，預設 scope 裡面有一個 profile 的項目
           options.Scope.Clear();

           //要讓 .net 預設的 openid 認證成功需要這個 Scope
           options.Scope.Add(OpenIdConnectScope.OpenId);

           // 從設定檔中取得 OAuth Scope
           foreach (var item in authOptions.WebApiAudience)
           {
               options.Scope.Add(item);
           }

           // 這個 scope 要求 Auth Server 回應 Refresh Token
           options.Scope.Add(OpenIdConnectScope.OfflineAccess);

           // if true , cookies ExpiresUtc will be use id_token expires time
           // options.UseTokenLifetime = true;

           options.SaveTokens = true;
           options.GetClaimsFromUserInfoEndpoint = true;

           options.TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" };

           // OpenIdConnect 套件預設 PKCE = True 以提升安全性
           // options.UsePkce = false; 
       });

//設定認證資料存放到 Redis 上面共用
//此範例未特別設定加密，基於安全性，應考慮加密問題
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
               // 將 openId 中取得的 Bearer Token 塞到 Header
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

// 攔截 favicon.ico 的路徑，因為 Proxy 的 Route 設定中尚未發現排除特定路徑的設定方式
app.Map("/favicon.ico", () => "");

app.UseW3CLogging();

app.UseRouting();

app.UseCors("CorsPolicy");

app.UseAuthentication();

app.UseAuthorization();

app.MapReverseProxy();

app.Run();