using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using CoreIdentity.API.Helpers;
using CoreIdentity.API.Identity.ViewModels;
using CoreIdentity.API.Services;
using CoreIdentity.API.Settings;
using Microsoft.Extensions.Options;
using CoreIdentity.API.Identity.Models;

namespace CoreIdentity.API.Identity.Controllers
{
    [Produces("application/json")]
    [Route("api/auth")]
    public class AuthController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ClientAppSettings _client;
        private readonly JwtSecurityTokenSettings _jwt;

        public AuthController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            IOptions<ClientAppSettings> client,
            IOptions<JwtSecurityTokenSettings> jwt
            )
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._configuration = configuration;
            this._emailService = emailService;
            this._client = client.Value;
            this._jwt = jwt.Value;
        }

        /// <summary>
        /// Confirms a user email address
        /// </summary>
        /// <param name="model">ConfirmEmailViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromBody]ConfirmEmailViewModel model)
        {

            if (model.UserId == null || model.Code == null)
            {
                return BadRequest(new string[] { "Error retrieving information!" });
            }

            var user = await _userManager.FindByIdAsync(model.UserId).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Could not find user!" });

            var result = await _userManager.ConfirmEmailAsync(user, model.Code).ConfigureAwait(false);
            if (result.Succeeded)
                return Ok(result);

            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Register an account
        /// </summary>
        /// <param name="model">RegisterViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody]RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);
                var callbackUrl = $"{_client.Url}{_client.EmailConfirmationPath}?uid={user.Id}&code={System.Net.WebUtility.UrlEncode(code)}";

                await _emailService.SendEmailConfirmationAsync(model.Email, callbackUrl).ConfigureAwait(false);

                return Ok();
            }

            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Log into account
        /// </summary>
        /// <param name="model">LoginViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(TokenModel), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("token")]
        public async Task<IActionResult> CreateToken([FromBody]LoginViewModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Invalid credentials." });

            var tokenModel = new TokenModel()
            {
                HasVerifiedEmail = false
            };

            // Only allow login if email is confirmed
            if (!user.EmailConfirmed)
            {
                return Ok(tokenModel);
            }

            // Used as user lock
            if (user.LockoutEnabled)
                return BadRequest(new string[] { "This account has been locked." });

            if (await _userManager.CheckPasswordAsync(user, model.Password).ConfigureAwait(false))
            {
                tokenModel.HasVerifiedEmail = true;

                if (user.TwoFactorEnabled)
                {
                    tokenModel.TFAEnabled = true;
                    return Ok(tokenModel);
                }
                else
                {
                    JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user).ConfigureAwait(false);
                    tokenModel.TFAEnabled = false;
                    tokenModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

                    return Ok(tokenModel);
                }
            }

            return BadRequest(new string[] { "Invalid login attempt." });
        }

        /// <summary>
        /// Log in with TFA 
        /// </summary>
        /// <param name="model">LoginWith2faViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(TokenModel), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("tfa")]
        public async Task<IActionResult> LoginWith2fa([FromBody]LoginWith2faViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Invalid credentials." });

            if (await _userManager.VerifyTwoFactorTokenAsync(user, "Authenticator", model.TwoFactorCode).ConfigureAwait(false))
            {
                JwtSecurityToken jwtSecurityToken = await CreateJwtToken(user).ConfigureAwait(false);

                var tokenModel = new TokenModel()
                {
                    HasVerifiedEmail = true,
                    TFAEnabled = false,
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
                };

                return Ok(tokenModel);
            }
            return BadRequest(new string[] { "Unable to verify Authenticator Code!" });
        }

        /// <summary>
        /// Forgot email sends an email with a link containing reset token
        /// </summary>
        /// <param name="model">ForgotPasswordViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("forgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromBody]ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user).ConfigureAwait(false)))
                return BadRequest(new string[] { "Please verify your email address." });

            var code = await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false);
            var callbackUrl = $"{_client.Url}{_client.ResetPasswordPath}?uid={user.Id}&code={System.Net.WebUtility.UrlEncode(code)}";

            await _emailService.SendPasswordResetAsync(model.Email, callbackUrl).ConfigureAwait(false);

            return Ok();
        }

        /// <summary>
        /// Reset account password with reset token
        /// </summary>
        /// <param name="model">ResetPasswordViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(typeof(IdentityResult), 200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("resetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody]ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState.Values.Select(x => x.Errors.FirstOrDefault().ErrorMessage));

            var user = await _userManager.FindByIdAsync(model.UserId).ConfigureAwait(false);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return BadRequest(new string[] { "Invalid credentials." });
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password).ConfigureAwait(false);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result.Errors.Select(x => x.Description));
        }

        /// <summary>
        /// Resend email verification email with token link
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(typeof(IEnumerable<string>), 400)]
        [Route("resendVerificationEmail")]
        public async Task<IActionResult> resendVerificationEmail([FromBody]UserViewModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
            if (user == null)
                return BadRequest(new string[] { "Could not find user!" });

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);
            var callbackUrl = $"{_client.Url}{_client.EmailConfirmationPath}?uid={user.Id}&code={System.Net.WebUtility.UrlEncode(code)}";
            await _emailService.SendEmailConfirmationAsync(user.Email, callbackUrl).ConfigureAwait(false);

            return Ok();
        }

        private async Task<JwtSecurityToken> CreateJwtToken(IdentityUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);
            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);

            var roleClaims = new List<Claim>();

            for (int i = 0; i < roles.Count; i++)
            {
                roleClaims.Add(new Claim("roles", roles[i]));
            }

            string ipAddress = IpHelper.GetIpAddress();

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id),
                new Claim("ip", ipAddress)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }
    }
}