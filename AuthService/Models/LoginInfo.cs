
using System.Collections.Generic;
using Newtonsoft.Json;

namespace AuthService.Models
{
public class LoginInfo
    {
       [Newtonsoft.Json.JsonProperty("email")]
        public string Email { get; set; }

        [Newtonsoft.Json.JsonProperty("accessCode")]
        public string AccessCode { get; set; }

  
        public LoginInfo(string email, string accessCode)
        {
            
            this.Email = email;
            this.AccessCode = accessCode;
        }
    }
}
    