using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CoreIdentity.API.Helpers
{
    public class UserHelper
    {
        public static string GetUserId(ClaimsPrincipal User)
        {
            return User.FindFirst("uid")?.Value;
        }

        public static string GetUserEmail(ClaimsPrincipal User)
        {
            return User.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
        }
    }
}
