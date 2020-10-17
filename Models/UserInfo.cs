using System.Collections.Generic;

namespace KalumAutenticacion.Models
{
    public class UserInfo
    {
        public string Id {get;set;}
        public string UserName {get;set;}
        public string NormalizedUserName {get;set;}
        public string Email {get;set;}        
        public string Password {get;set;}
        public IList<string> roles {get;set;}
    }
}