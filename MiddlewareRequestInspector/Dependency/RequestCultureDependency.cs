using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RequestCultureMiddleware.Service;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RequestCultureMiddleware.Dependency
{
    public static class RequestCultureDependency
    {
        public static void AddRequestCultureDependency(this IServiceCollection services, IConfiguration configuration, IHostBuilder host)
        {
            services.AddSingleton<ITypedClientConfig, TypedClientConfig>();
            services.AddScoped<IGrpcServiceClient, GrpcServiceClient>();

            host.UseServiceProviderFactory(new AutofacServiceProviderFactory());

            host.ConfigureContainer<ContainerBuilder>((context, builder) =>
            {
                builder.RegisterType<HttpContextAccessor>().As<IHttpContextAccessor>().SingleInstance();
            });
        }
    }
}
