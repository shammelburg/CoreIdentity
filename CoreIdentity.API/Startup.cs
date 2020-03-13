using CoreIdentity.API.Helpers;
using CoreIdentity.API.Identity;
using CoreIdentity.API.Middleware;
using CoreIdentity.API.Services;
using CoreIdentity.API.Settings;
using CoreIdentity.Azure.Storage.Interfaces;
using CoreIdentity.Azure.Storage.Services;
using CoreIdentity.Data;
using CoreIdentity.Data.Interfaces;
using CoreIdentity.Data.Repos;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CoreIdentity.API
{
    // ref #1: https://logcorner.com/token-based-authentication-using-asp-net-web-api-core/
    // ref #2: https://social.technet.microsoft.com/wiki/contents/articles/36804.asp-net-core-mvc-authentication-and-role-based-authorization-with-asp-net-core-identity.aspx#Add_Edit_Application_Role
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Identity
            services.AddDbContext<SecurityContext>(options => options.UseSqlServer(Configuration["ConnectionStrings:Default"]));

            // Tools->NuGet Package Manager -> Package Manager Console
            // Initialise
            // add-migration init -Context SecurityContext
            // update or create DB
            // update-database -Context SecurityContext
            IdentityHelper.ConfigureService(services);

            // Helpers
            AuthenticationHelper.ConfigureService(services, Configuration["JwtSecurityToken:Issuer"], Configuration["JwtSecurityToken:Audience"], Configuration["JwtSecurityToken:Key"]);
            CorsHelper.ConfigureService(services);
            SwaggerHelper.ConfigureService(services);

            // Settings
            services.Configure<EmailSettings>(Configuration.GetSection("Email"));
            services.Configure<ClientAppSettings>(Configuration.GetSection("ClientApp"));
            services.Configure<JwtSecurityTokenSettings>(Configuration.GetSection("JwtSecurityToken"));
            services.Configure<QRCodeSettings>(Configuration.GetSection("QRCode"));

            // Services
            services.AddTransient<IEmailService, EmailService>();

            // Azure
            // Azure Storage Services
            services.AddScoped<IBlobStorage>(s => new BlobStorage(Configuration["ConnectionStrings:AzureStorage"], Configuration["AzureStorage:ContainerName"], Configuration["AzureStorage:Url"]));
            services.AddScoped<IQueueStorage>(s => new QueueStorage(Configuration["ConnectionStrings:AzureStorage"]));

            // Data
            services.AddDbContextPool<DataContext>(options => options.UseSqlServer(Configuration["ConnectionStrings:Default"]));
            services.AddScoped<IExampleRepo, ExampleRepo>();

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseErrorHandlingMiddleware();

            // Use WhiteList
            // app.UseWhiteListMiddleware(Configuration["AllowedIPs"]);

            app.UseRouting();

            app.UseCors("CorsPolicy");
            app.UseAuthentication();
            app.UseAuthorization();

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Web API V1");
                c.RoutePrefix = "";
            });

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
