using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RequestCultureMiddleware.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace RequestCultureMiddleware.Dependency
{
    public static class HttpClientFactory
    {
        public static void AddHttpClientInFactory(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddConfiguredHttpClient<IGrpcServiceClient, GrpcServiceClient>();
        }

        private static void AddConfiguredHttpClient<TClient, TImplementation>(this IServiceCollection services)
        where TClient : class
        where TImplementation : class, TClient
        {
            services.AddHttpClient<TClient, TImplementation>()
                    .ConfigureHttpClient(ConfigureHttpClient)
                    .SetHandlerLifetime(TimeSpan.FromMinutes(5)) 
                    .ConfigurePrimaryHttpMessageHandler(GetHttpClientHandler);
        }

        private static void ConfigureHttpClient(IServiceProvider serviceProvider, HttpClient httpClient)
        {
            var clientConfig = serviceProvider.GetRequiredService<ITypedClientConfig>();
            httpClient.BaseAddress = clientConfig.BaseUrl;
            httpClient.Timeout = TimeSpan.FromSeconds(clientConfig.Timeout);
            httpClient.DefaultRequestHeaders.Add("User-Agent", "BlahAgent");
            httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        private static HttpClientHandler GetHttpClientHandler()
        {
            return new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
                UseCookies = false,
                AllowAutoRedirect = false,
                UseDefaultCredentials = true,
            };
        }
    }
}
