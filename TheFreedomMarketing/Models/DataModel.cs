using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace TheFreedomMarketing.Models
{
    public class DataModel
    {
        public class Roles
        {
            [Key]
            public int idRoles { get; set; }
            public string Descripcion { get; set; }
            public string FechaCreacion { get; set; }
            public string CodigoRol { get; set; }
        }
        public class Usuarios
        {
            [Key]
            public int idUsuarios { get; set; }
            public string CodigoUsuario { get; set; }
            public string PrimerNombre { get; set; }
            public string SegundoNombre { get; set; }
            public string PrimerApellido { get; set; }
            public string SegundoApellido { get; set; }
            public string Identificacion { get; set; }
            public string CorreoElectronico { get; set; }
            public string Telefono { get; set; }
            public string Direccion { get; set; }
            public string Pais { get; set; }
            public string CodigoReferencia { get; set; }
            public int Puntos { get; set; }
            public string CodigoRol { get; set; }
            public bool Estado { get; set; }
            public string CuentadePago { get; set; }
            public string FechaCreacion { get; set; }
            public string Contraseña { get; set; }
            public bool CorreoMasivo { get; set; }
        }
        public class ResponseModel
        {
            public object HttpResponse { get; set; }
            public object FreedomResponse { get; set; }
        }
        public class LoginResponse
        {
            public string CorreoElectronico { get; set; }
            public string NombreCompleto { get; set; }
            public string Rol { get; set; }
        }
    }
}