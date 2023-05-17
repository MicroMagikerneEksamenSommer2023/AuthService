using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections.Generic;

namespace AuthService.Models
{
public class LoginInfo
    {
        [BsonId]
        [BsonElement(elementName:"_id")]
        public ObjectId Id { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
    }
}
    