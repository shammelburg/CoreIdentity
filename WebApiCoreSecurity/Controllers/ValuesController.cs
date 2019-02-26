using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace WebApiCoreSecurity.Controllers
{
    [Produces("application/json")]
    [Route("api/values")]
    public class ValuesController : Controller
    {
        // GET: api/Values
        [HttpGet]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value3" };
        }

        // GET: api/Values/5
        [HttpGet]
        [Route("{id}")]
        public string Get(int id)
        {
            return "value";
        }
        
        // POST: api/Values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }
        
        // PUT: api/Values/5
        [HttpPut]
        [Route("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }
        
        // DELETE: api/ApiWithActions/5
        [HttpDelete]
        [Route("{id}")]
        public void Delete(int id)
        {
        }
    }
}
