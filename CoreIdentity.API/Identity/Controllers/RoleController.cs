using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using CoreIdentity.API.Identity.ViewModels;
using System.Collections.Generic;
using System.Linq;

namespace CoreIdentity.API.Identity.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
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
        public IActionResult Get() => Ok(
            _roleManager.Roles
            .Select(role => new
            {
                role.Id,
                role.Name
            }));

        /// <summary>
        /// Insert a role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("insert")]
        public async Task<IActionResult> Post([FromBody]RoleViewModel model)
        {
            if (model == null)
                return BadRequest(new string[] { "No data in model!" });

            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            IdentityRole identityRole = new IdentityRole { Name = model.Name };

            IdentityResult result = await _roleManager.CreateAsync(identityRole).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    identityRole.Id,
                    identityRole.Name
                });
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Update a role
        /// </summary>
        /// <param name="Id">Role Id</param>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPut]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("update/{Id}")]
        public async Task<IActionResult> Put(string Id, [FromBody]RoleViewModel model)
        {
            if (model == null)
                return BadRequest(new string[] { "No data in model!" });

            IdentityRole identityRole = await _roleManager.FindByIdAsync(Id).ConfigureAwait(false);

            identityRole.Name = model.Name;

            IdentityResult result = await _roleManager.UpdateAsync(identityRole).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Delete a role
        /// </summary>
        /// <param name="Id"></param>
        /// <returns></returns>
        [HttpDelete]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("delete/{Id}")]
        public async Task<IActionResult> Delete(string Id)
        {
            if (String.IsNullOrEmpty(Id))
                return BadRequest(new string[] { "Could not complete request!" });

            IdentityRole identityRole = await _roleManager.FindByIdAsync(Id).ConfigureAwait(false);
            if (identityRole == null)
                return BadRequest(new string[] { "Could not find role!" });

            IdentityResult result = await _roleManager.DeleteAsync(identityRole).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }
    }
}