using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CoreIdentity.Settings
{
    public class EmailSettings
    {
        public bool DefaultCredentials { get; set; }
        public string To { get; set; }
        public string From { get; set; }
        public string SMTPServer { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public int Port { get; set; }
    }
}
