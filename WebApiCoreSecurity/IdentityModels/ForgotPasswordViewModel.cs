using System.ComponentModel.DataAnnotations;

namespace WebApiCoreSecurity.IdentityModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
