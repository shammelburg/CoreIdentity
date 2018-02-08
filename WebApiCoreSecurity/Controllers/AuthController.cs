using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebApiCoreSecurity.ViewModels;

namespace WebApiCoreSecurity.Controllers
{
    [Produces("application/json")]
    [Route("api/Auth")]
    public class AuthController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private IPasswordHasher<IdentityUser> _passwordHasher;
        private IConfiguration _configuration;

        public AuthController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IPasswordHasher<IdentityUser> passwordHasher,
            IConfiguration configuration
            )
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._signInManager = signInManager;
            this._passwordHasher = passwordHasher;
            this._configuration = configuration;
        }


        //[AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody]RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Model is invalid!");

            var user = new IdentityUser { UserName = model.UserName, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                //var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                //await _emailSender.SendEmailConfirmationAsync(model.Email, callbackUrl);

                //await _signInManager.SignInAsync(user, isPersistent: false);

                return Ok(new
                {
                    Result = result,
                    EmailConfirmationCode = code
                });
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("error", error.Description);
            }

            return BadRequest(result);
        }

        //[ValidateForm]
        [HttpPost("CreateToken")]
        [Route("token")]
        public async Task<IActionResult> CreateToken([FromBody]LoginViewModel vm)
        {
            var user = await _userManager.FindByNameAsync(vm.UserName);
            if (user == null)
                return BadRequest("Invalid login attempt.");

            // Only allow login if email is confirmed
            if (!user.EmailConfirmed)
                return BadRequest("You must have a confirmed email to log in.");

            if (user.LockoutEnabled)
                return BadRequest("This account has been locked.");

            if (await _userManager.CheckPasswordAsync(user, vm.Password))
            {
                if (user.TwoFactorEnabled)
                {
                    return Ok(new
                    {
                        TwoFA = user.TwoFactorEnabled,
                        Url = "api/auth/2fa"
                    });
                }
                else
                {
                    JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
                    return Ok(new
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                        Expiration = jwtSecurityToken.ValidTo
                    });
                }
            }

            return BadRequest("Invalid login attempt.");
        }

        [HttpPost("LoginWith2fa")]
        [AllowAnonymous]
        [Route("2fa")]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, string returnUrl = null)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if(user == null)
                return BadRequest("Could not continue with this request. (E1)");

            if (await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", model.TwoFactorCode))
            {
                JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user);
                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                    Expiration = jwtSecurityToken.ValidTo
                });
            }
            return BadRequest("Unable to verify Authenticator Code!");
        }



        private async Task<JwtSecurityToken> CreateJwtToken(IdentityUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            var roleClaims = new List<Claim>();

            for (int i = 0; i < roles.Count; i++)
            {
                roleClaims.Add(new Claim("roles", roles[i]));
            }

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);


            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSecurityToken:Key"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _configuration["JwtSecurityToken:Issuer"],
                audience: _configuration["JwtSecurityToken:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }


        [HttpPost]
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest("Could not continue with this request. (E2)");

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                return BadRequest("Could not continue with this request. (E1)");

            // For more information on how to enable account confirmation and password reset please
            // visit https://go.microsoft.com/fwlink/?LinkID=532713
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            //var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
            //await _emailSender.SendEmailAsync(model.Email, "Reset Password",
            //   $"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
            return Ok(new
            {
                Message = $"Please reset your password by clicking here: <a href=''>link</a>",
                Code = code
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ResetPassword")]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return BadRequest("Could not continue with this request. (E1)");
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string Id, string code)
        {
            if (Id == null || code == null)
                return BadRequest("Error retrieving information!");

            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
                return BadRequest("Could not find user!");

            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
                return Ok(result.Succeeded);
            return BadRequest(result);
        }
    }
}