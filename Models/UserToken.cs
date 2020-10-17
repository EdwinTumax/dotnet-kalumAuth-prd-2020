using System;

namespace KalumAutenticacion.Models
{
    public class UserToken
    {
        public string Token {get;set;}
        public DateTime Expiration {get;set;}
    }
}