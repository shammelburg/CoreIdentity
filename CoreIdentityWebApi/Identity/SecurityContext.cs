using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CoreIdentityWebApi.Identity
{
    public class SecurityContext : IdentityDbContext<IdentityUser>
    {
        public SecurityContext(DbContextOptions<SecurityContext> options)
            : base(options)
        {
            Database.EnsureCreated();
        }
    }
}
