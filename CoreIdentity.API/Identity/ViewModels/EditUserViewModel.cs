using System.ComponentModel.DataAnnotations;

namespace CoreIdentity.API.Identity.ViewModels
{
    public class EditUserViewModel
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}
