using Autofac;
using Autofac.Extensions.DependencyInjection;
using Google.Api;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using NET_GRPC_SECURITY;
using NET_GRPC_SECURITY.Installers;
using NET_GRPC_SECURITY.Security;
using NET_SECURITY_DATAACCESS.Dapper;
using NET_SECURITY_DATAACCESS.Entities;
using NET_SECURITY_DATAACCESS.UnitOfWork;
using WAF_SECURITY.DOSSecurity;
using WAF_SECURITY.FileUploadSecurity;
using WAF_SECURITY.SQLISecurity;
using WAF_SECURITY.XSSSecurity;

namespace NET_GRPC_SECURITY
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<NET_SECURITY_DATAACCESS.Entities.NetsecurityContext>(option => option.UseSqlite(builder.Configuration.GetConnectionString("SqlConnection")));
            builder.Services.AddGrpc().AddJsonTranscoding();
            builder.Services.AddMemoryCache();

            builder.Services.InstallerServicesInAssembly(builder.Configuration);

            builder.Services.AddSingleton<ITokenBucket>(new TokenBucket(maxNumberOfTokens: builder.Configuration.GetValue<int>("AppConfiguration:TokenBucket:MaxNumberOfTokens"), refillRateInMilliseconds: builder.Configuration.GetValue<int>("AppConfiguration:TokenBucket:RefillRateInMilliseconds")));

            builder.Host.UseServiceProviderFactory(new AutofacServiceProviderFactory());

            // Call ConfigureContainer on the Host sub property 
            builder.Host.ConfigureContainer<ContainerBuilder>(builder =>
            {
                builder.RegisterType<NetsecurityContext>().AsSelf();
                builder.RegisterType<UnitOfWork>().As<IUnitOfWork>();
                builder.RegisterType<DapperContext>().As<IDapperContext>();
                builder.RegisterType<SQLITesting>().As<ISQLITesting>();
                builder.RegisterType<FileUploadTesting>().As<IFileUploadTesting>();
                builder.RegisterType<XSSTesting>().As<IXSSTesting>();
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            app.MapGrpcService<ProtobufSecurity>();
            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");

            app.Run();
        }
    }
}