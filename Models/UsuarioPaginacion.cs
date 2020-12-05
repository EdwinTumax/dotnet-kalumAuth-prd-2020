using System.Collections.Generic;

namespace KalumAutenticacion.Models
{
    public class UsuarioPaginacion
    {
        public int Number {get;set;}
        public bool First {get;set;}
        public int TotalPages {get;set;}
        public bool Last {get;set;}
        public List<UserInfo> Content {get;set;}

    }
}