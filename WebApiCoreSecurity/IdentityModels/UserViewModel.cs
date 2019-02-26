using System.ComponentModel.DataAnnotations;

namespace WebApiCoreSecurity.IdentityModels
{
    public class UserViewModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
        public string Email { get; set; }
        public string ApplicationRoleId { get; set; }
        public string UserId { get; set; }
        public string RoleId { get; set; }
    }
}
