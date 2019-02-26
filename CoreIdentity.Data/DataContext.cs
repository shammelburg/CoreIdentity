using CoreIdentity.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace CoreIdentity.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        { }

        // Stored Procedures or tables
        public DbSet<spGetOneExample> spGetOneExample { get; set; }
        public DbSet<spGetManyExamples> spGetManyExamples { get; set; }
    }
}
