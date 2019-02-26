using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using CoreIdentity.API.Identity.ViewModels;

namespace CoreIdentity.API.Identity.Controllers
{
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
        [Route("get/{Id}")]
        public async Task<IActionResult> Get(string Id)
        {
            IdentityUser user = await _userManager.FindByIdAsync(Id);
            return Ok(await _userManager.GetRolesAsync(user));
        }

        /// <summary>
        /// Add a user to existing role
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("add")]
        public async Task<IActionResult> Post([FromBody]UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
                return BadRequest("Could not find user!");

            IdentityRole role = await _roleManager.FindByIdAsync(model.ApplicationRoleId);
            if (role == null)
                return BadRequest("Could not find role!");

            IdentityResult result = await _userManager.AddToRoleAsync(user, role.Name);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        /// <summary>
        /// Remove a user from an existing role
        /// </summary>
        /// <param name="Id"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpDelete]
        [Route("remove")]
        public async Task<IActionResult> Delete(string Id, [FromBody]UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = await _userManager.FindByIdAsync(Id);
            if (user == null)
                return BadRequest("Could not find user!");

            string existingRole = _userManager.GetRolesAsync(user).Result.Single();
            string existingRoleId = _roleManager.Roles.Single(r => r.Name == existingRole).Id;

            if (existingRoleId == model.ApplicationRoleId)
            {
                IdentityResult result = await _userManager.RemoveFromRoleAsync(user, existingRole);
                if (result.Succeeded)
                {
                    return Ok(result);
                }
                return BadRequest(result);
            }

            return BadRequest("Could not complete request!");
        }
    }
}