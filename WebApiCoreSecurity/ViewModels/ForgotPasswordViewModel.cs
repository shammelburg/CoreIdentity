using System.ComponentModel.DataAnnotations;

namespace WebApiCoreSecurity.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
