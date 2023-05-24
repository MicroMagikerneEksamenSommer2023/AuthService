using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace AuthService.Models
{
public class LoginInfo
    {
        [Newtonsoft.Json.JsonProperty("email")]
        public string Email { get; set; }
        [Newtonsoft.Json.JsonProperty("password")]
        public string Password { get; set; }

        [JsonConstructor]
        public LoginInfo(string email, string password)
        {
            this.Email = email;
            this.Password = password;
        }
    }
}
    