using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Swagger;
using System;
using System.IO;
using System.Reflection;
using System.Text;
using CoreIdentity.API.Identity;
using CoreIdentity.API.Settings;
using CoreIdentity.API.Services;
using CoreIdentity.API.Middleware;
using CoreIdentity.API.Helpers;
using CoreIdentity.Data;
using CoreIdentity.Data.Interfaces;
using CoreIdentity.Data.Repos;

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

            // Data
            services.AddDbContextPool<DataContext>(options => options.UseSqlServer(Configuration["ConnectionStrings:Default"]));
            services.AddScoped<IExampleRepo, ExampleRepo>();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Use WhiteList
            // app.UseWhiteListMiddleware(Configuration["AllowedIPs"]);

            app.UseAuthentication();
            app.UseCors("CorsPolicy");
            app.UseErrorHandlingMiddleware();

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Web API V1");
                c.RoutePrefix = "";
            });

            app.UseMvc();
        }
    }
}
