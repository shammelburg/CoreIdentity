using System.ComponentModel.DataAnnotations;

namespace WebApiCoreSecurity.IdentityModels
{
    public class EnableAuthenticatorViewModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        public string Code { get; set; }
        
        public string SharedKey { get; set; }
        
        public string AuthenticatorUri { get; set; }
    }
}
