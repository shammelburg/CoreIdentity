using System.ComponentModel.DataAnnotations;

namespace WebApiCoreSecurity.Identity.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
