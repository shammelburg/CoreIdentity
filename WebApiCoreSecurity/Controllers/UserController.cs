using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;
using WebApiCoreSecurity.ViewModels;

namespace WebApiCoreSecurity.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/User")]
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager
            )
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult Get()
        {
            return Ok(_userManager.Users);
        }

        [HttpGet("{Id}")]
        public IActionResult Get(string Id)
        {
            if (String.IsNullOrEmpty(Id))
                return BadRequest("Empty parameter!");

            return Ok(_userManager.Users.Where(user => user.Id == Id));
        }

        [HttpPost]
        [Route("InsertWithRole")]
        public async Task<IActionResult> Post([FromBody]UserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = new IdentityUser
            {
                UserName = model.UserName,
                Email = model.Email
            };

            IdentityResult result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                IdentityRole role = await _roleManager.FindByIdAsync(model.ApplicationRoleId);
                if (role == null)
                    return BadRequest("Could not find role!");

                IdentityResult result2 = await _userManager.AddToRoleAsync(user, role.Name);
                if (result2.Succeeded)
                {
                    return Ok(result2);
                }
                return BadRequest(result2);

            }
            return BadRequest(result);
        }

        [HttpPost]
        [Route("Update")]
        public async Task<IActionResult> Put(string Id, [FromBody]EditUserViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            IdentityUser user = await _userManager.FindByIdAsync(Id);
            if (user == null)
                return BadRequest("Could not find user!");

            // Add more fields to update
            user.Email = model.Email;
            user.UserName = model.UserName;
            // ...
            // ...

            IdentityResult result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [HttpDelete]
        public async Task<IActionResult> DeleteUser(string Id)
        {
            if (!String.IsNullOrEmpty(Id))
                return BadRequest("Empty parameter!");

            IdentityUser user = await _userManager.FindByIdAsync(Id);
            if (user == null)
                return BadRequest("Could not find user!");

            IdentityResult result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }
    }
}
