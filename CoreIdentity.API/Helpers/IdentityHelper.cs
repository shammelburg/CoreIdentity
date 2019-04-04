using CoreIdentity.API.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreIdentity.API.Helpers
{
    public class IdentityHelper
    {
        public static void ConfigureService(IServiceCollection service)
        {
            service.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<SecurityContext>()
                .AddDefaultTokenProviders();

            // Initialise
            // add-migration init -Context SecurityContext
            // update or create DB
            // update-database -Context SecurityContext
            // 1. Tools->NuGet Package Manager -> Package Manager Console.
            // 2. Run PM> Add - Migration MyFirstMigration to scaffold a migration to create the initial set of tables for our model. If we receive an error, which states the term `add - migration' is not recognized as the name of a cmdlet, then close and reopen Visual Studio.
            // 2. Run PM > Update - Database to apply the new migration to the database.Since our database doesn't exist yet, it will be created for us before the migration is applied.

            service.Configure<IdentityOptions>(options =>
            {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = false;
                options.Password.RequiredUniqueChars = 6;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 10;
                options.Lockout.AllowedForNewUsers = false;

                // User settings
                options.User.RequireUniqueEmail = true;
            });
        }
    }
}
