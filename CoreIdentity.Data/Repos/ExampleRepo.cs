using CoreIdentity.Data.Interfaces;
using CoreIdentity.Data.Models;
using CoreIdentity.Data.ViewModels;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreIdentity.Data.Repos
{
    public class ExampleRepo : IExampleRepo
    {
        private DataContext _ctx;

        public ExampleRepo(DataContext ctx)
        {
            _ctx = ctx;
        }

        public async Task<spGetOneExample> spGetOneExampleAsync(int Id)
        {
           var result = await _ctx.spGetOneExample.FromSqlInterpolated($"[dbo].[spGetOneExample] {Id}").ToListAsync();
            return result.FirstOrDefault();
        }

        public async Task<IEnumerable<spGetManyExamples>> spGetManyExamplesAsync()
        {
            return await _ctx.spGetManyExamples.FromSqlInterpolated($"[dbo].[spGetManyExamples]").ToListAsync();
        }

        public async Task<int> InsertExampleAsync(ExampleViewModel vm, string User)
        {
            return await _ctx.Database.ExecuteSqlInterpolatedAsync($"[dbo].[spInsertExample] {vm.Id}, {vm.Name}, {vm.DOB}, {vm.Active}, {User}");
        }

        public async Task<int> UpdateExampleAsync(int Id, ExampleViewModel vm, string User)
        {
            return await _ctx.Database.ExecuteSqlInterpolatedAsync($"[dbo].[spUpdateInsertExample] {Id}, {vm.Active}, {User}");
        }

        public async Task<int> DeleteExampleAsync(int Id, string User)
        {
            return await _ctx.Database.ExecuteSqlInterpolatedAsync($"[dbo].[spDeleteExample] {Id}, {User}");
        }
    }
}
