using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using CoreIdentity.API.Identity.ViewModels;
using System.Collections.Generic;

namespace CoreIdentity.API.Identity.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/role")]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            this._roleManager = roleManager;
        }


        /// <summary>
        /// Get all roles
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<IdentityRole>), 200)]
        [Route("get")]
        public IActionResult Get() => Ok(_roleManager.Roles);

        /// <summary>
        /// Insert a role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [Route("insert")]
        public async Task<IActionResult> Post([FromBody]RoleViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityRole identityRole = new IdentityRole
            {
                Name = model.RoleName
            };

            IdentityResult result = await _roleManager.CreateAsync(identityRole);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        /// <summary>
        /// Update a role
        /// </summary>
        /// <param name="Id">Role Id</param>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPut]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [Route("update/{Id}")]
        public async Task<IActionResult> Put(int Id, [FromBody]RoleViewModel model)
        {
            IdentityRole identityRole = await _roleManager.FindByIdAsync(model.Id);

            identityRole.Name = model.RoleName;

            IdentityResult result = await _roleManager.UpdateAsync(identityRole);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        /// <summary>
        /// Delete a role
        /// </summary>
        /// <param name="Id"></param>
        /// <returns></returns>
        [HttpDelete]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [Route("delete/{Id}")]
        public async Task<IActionResult> Delete(string Id)
        {
            if (String.IsNullOrEmpty(Id))
                return BadRequest("Could not complete request!");

            IdentityRole identityRole = await _roleManager.FindByIdAsync(Id);
            if (identityRole == null)
                return BadRequest("Could not find role!");

            IdentityResult result = _roleManager.DeleteAsync(identityRole).Result;
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }
    }
}