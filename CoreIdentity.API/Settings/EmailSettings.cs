using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreIdentity.API.Settings
{
    public class EmailSettings
    {
        public string To { get; set; }
        public string From { get; set; }
        public string DisplayName { get; set; }
        public string SendGridApiKey { get; set; }

    }
}
