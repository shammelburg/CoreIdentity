using CoreIdentity.Data.Interfaces;
using CoreIdentity.Data.Models;
using CoreIdentity.Data.ViewModels;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
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
            return await _ctx.spGetOneExample.FromSql($"[dbo].[spGetOneExample] {Id}").FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<spGetManyExamples>> spGetManyExamplesAsync()
        {
            return await _ctx.spGetManyExamples.FromSql($"[dbo].[spGetManyExamples]").ToListAsync();
        }

        public async Task<int> InsertExampleAsync(ExampleViewModel vm, string User)
        {
            return await _ctx.Database.ExecuteSqlCommandAsync($"[dbo].[spInsertExample] {vm.Id}, {vm.Name}, {vm.DOB}, {vm.Active}, {User}");
        }

        public async Task<int> UpdateExampleAsync(int Id, ExampleViewModel vm, string User)
        {
            return await _ctx.Database.ExecuteSqlCommandAsync($"[dbo].[spUpdateInsertExample] {Id}, {vm.Active}, {User}");
        }

        public async Task<int> DeleteExampleAsync(int Id, string User)
        {
            return await _ctx.Database.ExecuteSqlCommandAsync($"[dbo].[spDeleteExample] {Id}, {User}");
        }
    }
}
