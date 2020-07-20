using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using CoreIdentity.API.Identity.ViewModels;
using System.Collections.Generic;

namespace CoreIdentity.API.Identity.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [Produces("application/json")]
    [Route("api/userRoles")]
    public class UserRolesController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserRolesController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager
            )
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
        }

        /// <summary>
        /// Get a user roles
        /// </summary>
        /// <param name="Id"></param>
        /// <returns></returns>
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<string>), 200)]
        [Route("get/{Id}")]
        public async Task<IActionResult> Get(string Id)
        {
            IdentityUser user = await _userManager.FindByIdAsync(Id).ConfigureAwait(false);
            return Ok(await _userManager.GetRolesAsync(user).ConfigureAwait(false));
        }

        /// <summary>
        /// Add a user to existing role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("add")]
        public async Task<IActionResult> Post([FromBody]UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            IdentityUser user = await _userManager.FindByIdAsync(model.Id).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Could not find user!" });

            IdentityRole role = await _roleManager.FindByIdAsync(model.RoleId).ConfigureAwait(false);
            if (role == null)
                return BadRequest(new string[] { "Could not find role!" });

            IdentityResult result = await _userManager.AddToRoleAsync(user, role.Name).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok(role.Name);
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Delete a user from an existing role
        /// </summary>
        /// <param name="Id"></param>
        /// <param name="RoleId"></param>
        /// <returns></returns>
        [HttpDelete]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("delete/{Id}/{RoleId}")]
        public async Task<IActionResult> Delete(string Id, string RoleId)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            IdentityUser user = await _userManager.FindByIdAsync(Id).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Could not find user!" });

            IdentityRole role = await _roleManager.FindByIdAsync(RoleId).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Could not find role!" });

            IdentityResult result = await _userManager.RemoveFromRoleAsync(user, role.Name).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }
    }
}
