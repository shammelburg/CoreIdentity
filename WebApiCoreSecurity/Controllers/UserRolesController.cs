using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiCoreSecurity.ViewModels;

namespace WebApiCoreSecurity.Controllers
{
    [Produces("application/json")]
    [Route("api/UserRoles")]
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

        [HttpGet("{Id}")]
        [AllowAnonymous]
        [Route("GetUserRoles")]
        public async Task<IActionResult> Get(string Id)
        {
            IdentityUser user = await _userManager.FindByIdAsync(Id);
            return Ok(await _userManager.GetRolesAsync(user));
        }

        [HttpPost("Post")]
        [AllowAnonymous]
        [Route("AddToRole")]
        public async Task<IActionResult> Post(UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid model!");

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

        [HttpDelete("Delete")]
        [AllowAnonymous]
        [Route("RemoveFromRole")]
        public async Task<IActionResult> Delete(string Id, UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid model!");

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