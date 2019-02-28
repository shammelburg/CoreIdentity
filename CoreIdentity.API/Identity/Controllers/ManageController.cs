using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using CoreIdentity.API.Identity.ViewModels;
using CoreIdentity.API.Services;
using CoreIdentity.API.Settings;
using Microsoft.Extensions.Options;

namespace CoreIdentity.API.Identity.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/manage")]
    public class ManageController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UrlEncoder _urlEncoder;
        private readonly IEmailService _emailService;
        private readonly ClientAppSettings _client;

        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        public ManageController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            UrlEncoder urlEncoder,
            IEmailService emailService,
            IOptions<ClientAppSettings> client
            )
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
            this._urlEncoder = urlEncoder;
            this._emailService = emailService;
            this._client = client.Value;
        }

        /// <summary>
        /// Get user information
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("userInfo")]
        public async Task<IActionResult> UserInfo()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);

            var userModel = new
            {
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                LockoutEnabled = user.LockoutEnabled,
                Roles = await _userManager.GetRolesAsync(user)
            };

            return Ok(userModel);
        }

        /// <summary>
        /// Get TFA stats
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("twoFactorAuthentication")]
        public async Task<IActionResult> TwoFactorAuthentication()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var model = new TwoFactorAuthenticationViewModel
            {
                HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null,
                Is2faEnabled = user.TwoFactorEnabled,
                RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user),
            };

            return Ok(model);
        }

        /// <summary>
        /// https://docs.microsoft.com/en-us/aspnet/core/security/authentication/identity-enable-qrcodes
        /// http://jakeydocs.readthedocs.io/en/latest/security/authentication/2fa.html#log-in-with-two-factor-authentication
        /// </summary>
        /// <returns>QR Code</returns>
        [HttpGet]
        [Route("enableAuthenticator")]
        public async Task<IActionResult> EnableAuthenticator()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var model = new EnableAuthenticatorViewModel();
            await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return Ok(model);
        }

        /// <summary>
        /// Change password for authenticated user
        /// </summary>
        /// <param name="model">ChangePasswordViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [Route("changePassword")]
        public async Task<IActionResult> ChangePassword([FromBody]ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
            if (!changePasswordResult.Succeeded)
                return BadRequest("Could not change password!");

            return Ok(changePasswordResult);
        }

        /// <summary>
        /// Send email verification email
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("sendVerificationEmail")]
        public async Task<IActionResult> SendVerificationEmail()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = $"{_client.Url}{_client.EmailConfirmationPath}?uid={user.Id}&code={System.Net.WebUtility.UrlEncode(code)}";
            await _emailService.SendEmailConfirmationAsync(user.Email, callbackUrl);

            return Ok(new
            {
                //CallbackUrl = callbackUrl
            });
        }

        /// <summary>
        /// Set a password if the user doesn't have one already
        /// </summary>
        /// <param name="model">SetPasswordViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [Route("setPassword")]
        public async Task<IActionResult> SetPassword([FromBody]SetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var addPasswordResult = await _userManager.AddPasswordAsync(user, model.NewPassword);

            if (addPasswordResult.Succeeded)
                return Ok(addPasswordResult);

            return BadRequest(addPasswordResult);
        }

        /// <summary>
        /// Disable TFA
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("disableTfa")]
        public async Task<IActionResult> Disable2fa()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
                return BadRequest(new
                {
                    Result = disable2faResult,
                    Message = $"User with ID {user.Id} has disabled 2fa."
                });

            return Ok(disable2faResult);
        }

        /// <summary>
        /// Enable TFA (requires QR code)
        /// </summary>
        /// <param name="model">EnableAuthenticatorViewModel</param>
        /// <returns></returns>
        [HttpPost]
        [Route("enableAuthenticator")]
        public async Task<IActionResult> EnableAuthenticator([FromBody]EnableAuthenticatorViewModel model)
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return Ok(model);
            }

            // Strip spaces and hypens
            var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Code", "Verification code is invalid.");
                await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            //_logger.LogInformation("User with ID {UserId} has enabled 2FA with an authenticator app.", user.Id);
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            //TempData[RecoveryCodesKey] = recoveryCodes.ToArray();

            return Ok(recoveryCodes.ToArray());
        }

        //[HttpGet]
        //public IActionResult ShowRecoveryCodes()
        //{
        //    var recoveryCodes = (string[])TempData[RecoveryCodesKey];
        //    if (recoveryCodes == null)
        //    {
        //        return RedirectToAction(nameof(TwoFactorAuthentication));
        //    }

        //    var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes };
        //    return View(model);
        //}

        /// <summary>
        /// Reset TFA (This will reset and disable TFA)
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("resetAuthenticator")]
        public async Task<IActionResult> ResetAuthenticator()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            
            return Ok();
        }

        /// <summary>
        /// Generate new recovery codes (This will invalidate previous codes)
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("generateRecoveryCodes")]
        public async Task<IActionResult> GenerateRecoveryCodes()
        {
            var user = await _userManager.FindByIdAsync(User.FindFirst("uid")?.Value);
            if (user == null)
                return BadRequest("Could not find user!");

            if (!user.TwoFactorEnabled)
                return BadRequest($"Cannot generate recovery codes for user with ID '{user.Id}' as they do not have 2FA enabled.");

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            //_logger.LogInformation("User with ID {UserId} has generated new 2FA recovery codes.", user.Id);

            var model = new ShowRecoveryCodesViewModel { RecoveryCodes = recoveryCodes.ToArray() };

            return Ok(model);
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode("CoreIdentity.API"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }

        private async Task LoadSharedKeyAndQrCodeUriAsync(IdentityUser user, EnableAuthenticatorViewModel model)
        {
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = FormatKey(unformattedKey);
            model.AuthenticatorUri = GenerateQrCodeUri(user.Email, unformattedKey);
        }
    }
}
