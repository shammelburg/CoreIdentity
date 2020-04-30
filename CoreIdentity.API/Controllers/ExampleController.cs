using CoreIdentity.Data.Interfaces;
using CoreIdentity.Data.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace CoreIdentity.API.Controllers
{
    [Produces("application/json")]
    [Route("api/example")]
    public class ExampleController : Controller
    {
        private readonly IExampleRepo _repo;

        public ExampleController(IExampleRepo repo)
        {
            this._repo = repo;
        }

        // GET: api/example
        [HttpGet]
        [Route("get")]
        public async Task<IActionResult> Get() => Ok(await _repo.spGetManyExamplesAsync().ConfigureAwait(false));

        // GET: api/example/5
        [HttpGet]
        [Route("get/{Id}")]
        public async Task<IActionResult> Get(int Id) => Ok(await _repo.spGetOneExampleAsync(Id).ConfigureAwait(false));

        // POST: api/example
        [HttpPost]
        [Authorize]
        [Route("insert")]
        public async Task<IActionResult> Post([FromBody]ExampleViewModel model) => Ok(await _repo.InsertExampleAsync(model, User.FindFirst("uid")?.Value).ConfigureAwait(false));

        // PUT: api/example/5
        [HttpPut]
        [Route("update/{Id}")]
        public async Task<IActionResult> Put(int Id, [FromBody]ExampleViewModel model) => Ok(await _repo.UpdateExampleAsync(Id, model, User.FindFirst("uid")?.Value).ConfigureAwait(false));

        // DELETE: api/example/5
        [HttpDelete]
        [Route("delete/{Id}")]
        public async Task<IActionResult> Delete(int Id) => Ok(await _repo.DeleteExampleAsync(Id, User.FindFirst("uid")?.Value).ConfigureAwait(false));
    }
}
