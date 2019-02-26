using CoreIdentity.Data.Models;
using CoreIdentity.Data.ViewModels;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CoreIdentity.Data.Interfaces
{
    public interface IExampleRepo
    {
        Task<spGetOneExample> spGetOneExampleAsync(int Id);
        Task<IEnumerable<spGetManyExamples>> spGetManyExamplesAsync();
        Task<int> InsertExampleAsync(ExampleViewModel vm, string User);
        Task<int> UpdateExampleAsync(int Id, ExampleViewModel vm, string User);
        Task<int> DeleteExampleAsync(int Id, string User);
    }
}
