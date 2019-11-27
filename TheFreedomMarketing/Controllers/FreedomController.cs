using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Data.Entity;
using TheFreedomMarketing.Models;
using static TheFreedomMarketing.Models.DatabaseModel;
using static TheFreedomMarketing.Models.DataModel;
using TheFreedomMarketing.Security;

namespace TheFreedomMarketing.Controllers
{
    public class FreedomController : ApiController
    {
        private string cs = ConfigurationManager.ConnectionStrings["thefreedommarketing_dev"].ConnectionString;
        private readonly string _token;
        private readonly string _authHeader;
        private readonly JwtManager _jwt;
        private readonly HttpContext _httpContext;

        public FreedomController()
        {
            _jwt = new JwtManager();
            _httpContext = HttpContext.Current;
            _authHeader = _httpContext.Request.Headers["Authorization"];
            if (_authHeader != null)
            {
                if (_authHeader.StartsWith("Bearer ") || _authHeader.Contains("Bearer "))
                {
                    _token = _authHeader.Substring("Bearer ".Length).Trim();
                }
                else
                {
                    //Handle what happens if that isn't the case
                    // throw new Exception("The authorization header is either empty or isn't Bearer.");
                }
            }
        }

        [Route("wslogin")]
        [HttpPost]
        public HttpResponseMessage Login(Usuarios model)
        {
            MySqlContext db = new MySqlContext(cs);
            ResponseModel objresult = new ResponseModel();
            LoginResponse login = new LoginResponse();
            JwtManager jwt = new JwtManager();

            Usuarios results = (from x in db.Usuarios
                                where x.CorreoElectronico == model.CorreoElectronico && x.Contraseña == model.Contraseña
                                select x).FirstOrDefault();

            if(results == null)
            {
                objresult.FreedomResponse = new { serviceResponse = false, token = "" };
                objresult.HttpResponse = new { code = 401, message = "Contraseña o correo electronico invalido" };

                return Request.CreateResponse(HttpStatusCode.Unauthorized, objresult);
            }

            login.CorreoElectronico = results.CorreoElectronico;
            login.NombreCompleto = results.PrimerNombre + " " + results.PrimerApellido;

            var codigo = (from x in db.Roles
                          where x.CodigoRol == results.CodigoRol
                          select x.Descripcion).FirstOrDefault();

            login.Rol = codigo;

            objresult.FreedomResponse = new { serviceResponse = true, Data = login, token = jwt.GenerateCode(model.CorreoElectronico)};
            objresult.HttpResponse = new { code = 200, message = "Ok" };

            return Request.CreateResponse(HttpStatusCode.OK, objresult);
        }

        #region Roles

        [JwtAuthentication]
        [Route("wscrearrol")]
        [HttpPost]
        public HttpResponseMessage AgregarRoles(Roles model)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                model.CodigoRol = Guid.NewGuid().ToString();
                model.FechaCreacion = DateTime.UtcNow.AddHours(-5).ToString();

                db.Roles.Add(model);
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Route("wsmodificarrol")]
        [HttpPost]
        public HttpResponseMessage ModificarRoles(Roles model)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                Roles results = (from x in db.Roles
                                 where x.idRoles == model.idRoles
                                 select x).FirstOrDefault();

                if (!String.IsNullOrEmpty(model.Descripcion))
                    results.Descripcion = model.Descripcion;

                db.Entry(results).State = EntityState.Modified;
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Route("wseliminarrol")]
        [HttpDelete]
        public HttpResponseMessage EliminarRoles(int? rol = null)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                Roles results = (from x in db.Roles
                                 where x.idRoles == rol
                                 select x).FirstOrDefault();

                if (results == null)
                {
                    objresult.FreedomResponse = new { serviceResponse = false };
                    objresult.HttpResponse = new { code = 400, message = "El rol no existe en la base de datos" };

                    return Request.CreateResponse(HttpStatusCode.BadRequest, objresult);
                }

                db.Roles.Remove(results);
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Authorize]
        [Route("wslistarrol")]
        [HttpGet]
        public HttpResponseMessage ListarRoles(string rol = null)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                var results = (from x in db.Roles
                               where !String.IsNullOrEmpty(rol) ? x.Descripcion.Contains(rol) : x.Descripcion.Contains("")
                               select x).ToList();

                objresult.FreedomResponse = new { serviceResponse = true, Roles = results };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        #endregion

        #region Usuarios

        [JwtAuthentication]
        [Route("wscrearusuario")]
        [HttpPost]
        public HttpResponseMessage AgregarUsuario(Usuarios model)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                model.CodigoUsuario = Guid.NewGuid().ToString();
                model.FechaCreacion = DateTime.UtcNow.AddHours(-5).ToString();
                model.Puntos = 0;
                model.CodigoReferencia = "CR" + Guid.NewGuid().ToString();
                model.Estado = true;

                var codigo = (from x in db.Roles
                              where x.Descripcion == model.CodigoRol
                              select x.CodigoRol).FirstOrDefault();

                if (codigo == null)
                {
                    objresult.FreedomResponse = new { serviceResponse = false };
                    objresult.HttpResponse = new { code = 400, message = "El rol ingresado no existe en la base de datos" };

                    return Request.CreateResponse(HttpStatusCode.BadRequest, objresult);
                }

                model.CodigoRol = codigo;

                db.Usuarios.Add(model);
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Route("wsmodificarusuario")]
        [HttpPost]
        public HttpResponseMessage ModificarUsuario(Usuarios model)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                Usuarios results = (from x in db.Usuarios
                                 where x.idUsuarios == model.idUsuarios
                                 select x).FirstOrDefault();

                if (!String.IsNullOrEmpty(model.PrimerNombre))
                    results.PrimerNombre = model.PrimerNombre;

                if (!String.IsNullOrEmpty(model.SegundoNombre))
                    results.SegundoNombre = model.SegundoNombre;

                if (!String.IsNullOrEmpty(model.PrimerApellido))
                    results.PrimerApellido = model.PrimerApellido;

                if (!String.IsNullOrEmpty(model.SegundoApellido))
                    results.SegundoApellido = model.SegundoApellido;

                if (!String.IsNullOrEmpty(model.Identificacion))
                    results.Identificacion = model.Identificacion;

                if (!String.IsNullOrEmpty(model.CorreoElectronico))
                    results.CorreoElectronico = model.CorreoElectronico;

                if (!String.IsNullOrEmpty(model.Telefono))
                    results.Telefono = model.Telefono;

                if (!String.IsNullOrEmpty(model.Direccion))
                    results.Direccion = model.Direccion;

                if (!String.IsNullOrEmpty(model.Pais))
                    results.Pais = model.Pais;

                if (!String.IsNullOrEmpty(model.CodigoReferencia))
                    results.CodigoReferencia = model.CodigoReferencia;

                if (!String.IsNullOrEmpty(model.Puntos.ToString()))
                    results.Puntos = model.Puntos;

                if (!String.IsNullOrEmpty(model.CodigoRol))
                {
                    var codigo = (from x in db.Roles
                                  where x.Descripcion == model.CodigoRol
                                  select x.CodigoRol).FirstOrDefault();

                    if(codigo == null)
                    {
                        objresult.FreedomResponse = new { serviceResponse = false };
                        objresult.HttpResponse = new { code = 400, message = "El rol ingresado no existe en la base de datos" };

                        return Request.CreateResponse(HttpStatusCode.BadRequest, objresult);
                    }

                    model.CodigoRol = codigo;
                    results.CodigoRol = model.CodigoRol;
                }           

                if (!String.IsNullOrEmpty(model.Estado.ToString()))
                    results.Estado = model.Estado;

                if (!String.IsNullOrEmpty(model.CuentadePago))
                    results.CuentadePago = model.CuentadePago;

                if (!String.IsNullOrEmpty(model.Contraseña))
                    results.Contraseña = model.Contraseña;

                if (!String.IsNullOrEmpty(model.CorreoMasivo.ToString()))
                    results.CorreoMasivo = model.CorreoMasivo;

                db.Entry(results).State = EntityState.Modified;
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Route("wseliminarusuario")]
        [HttpDelete]
        public HttpResponseMessage EliminarUsuario(int? id = null)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                var results = (from x in db.Usuarios
                                where x.idUsuarios == id
                                select x).FirstOrDefault();

                if (results == null)
                {
                    objresult.FreedomResponse = new { serviceResponse = false };
                    objresult.HttpResponse = new { code = 400, message = "El usuario no existe en la base de datos" };

                    return Request.CreateResponse(HttpStatusCode.BadRequest, objresult);
                }

                db.Usuarios.Remove(results);
                db.SaveChanges();

                objresult.FreedomResponse = new { serviceResponse = true };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        [JwtAuthentication]
        [Route("wslistarusuarios")]
        [HttpGet]
        public HttpResponseMessage ListarUsuarios(string usuario = null)
        {
            try
            {
                MySqlContext db = new MySqlContext(cs);
                ResponseModel objresult = new ResponseModel();

                var results = (from x in db.Usuarios
                               where !String.IsNullOrEmpty(usuario) ? x.CorreoElectronico.Contains(usuario) : x.CorreoElectronico.Contains("")
                               select x).ToList();

                objresult.FreedomResponse = new { serviceResponse = true, Roles = results };
                objresult.HttpResponse = new { code = 200, message = "Ok" };

                return Request.CreateResponse(HttpStatusCode.OK, objresult);
            }
            catch (Exception e)
            {
                return Request.CreateResponse(HttpStatusCode.NotAcceptable, e.Message);
            }
        }

        #endregion
    }
}
