using System.ComponentModel.DataAnnotations;

namespace CoreIdentityWebApi.Identity.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
