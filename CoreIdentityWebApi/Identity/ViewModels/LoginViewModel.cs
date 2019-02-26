using System.ComponentModel.DataAnnotations;

namespace CoreIdentityWebApi.Identity.ViewModels
{
    public class LoginViewModel
    {
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
