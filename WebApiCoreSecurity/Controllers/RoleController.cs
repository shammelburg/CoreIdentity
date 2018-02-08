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
    [Route("api/Role")]
    public class RoleController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            this._roleManager = roleManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Get()
        {
            return Ok(_roleManager.Roles);
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("InsertUpdate")]
        public async Task<IActionResult> Post(RoleViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid model!");

            bool isExist = !String.IsNullOrEmpty(model.Id);

            IdentityRole identityRole = isExist ? await _roleManager.FindByIdAsync(model.Id) : new IdentityRole
            {
                Name = model.RoleName
            };

            identityRole.Name = model.RoleName;

            IdentityResult result = isExist ? await _roleManager.UpdateAsync(identityRole) : await _roleManager.CreateAsync(identityRole);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [HttpDelete]
        [AllowAnonymous]
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