using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using KalumAutenticacion.Context;
using KalumAutenticacion.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace KalumAutenticacion.Controllers
{
    [Route("KalumAutenticacion/v1/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]

    public class UsuariosController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly ApplicationDbContext context;
        public UsuariosController(UserManager<ApplicationUser> userManager, ApplicationDbContext context)
        {
            this.context = context;
            this.userManager = userManager;
        }
        [HttpGet]
        public async Task<ActionResult<List<UserInfo>>> Get()
        {
            var users = await userManager.Users.ToListAsync();

            if(users == null || users.Count == 0)
            {
                return NoContent();
            }
            List<UserInfo> usuarios = new List<UserInfo>();
            foreach (var item in users)
            {
                var userRoles = await userManager.GetRolesAsync(item);
            
                usuarios.Add(new UserInfo(){Id = item.Id, UserName = item.UserName, NormalizedUserName = item.NormalizedUserName, Email = item.Email, Password = item.PasswordHash, roles = userRoles  });
            }
            return usuarios;
        }

        [HttpGet("{numeroPagina}",Name = "GetUsuariosPage")]
        [Route("page/{numeroPagina}")]
        public async Task<ActionResult<UsuarioPaginacion>> GetUsuariosPage(int numeroPagina = 0)
        {
            int cantidadRegistros = 5;        
            var query = this.context.Users.AsQueryable();
            int totalRegistros = await query.CountAsync();
            int totalPaginas = (int) Math.Ceiling((Double) totalRegistros / cantidadRegistros);
            var users = await query.Skip(cantidadRegistros * numeroPagina)
                .Take(cantidadRegistros).ToListAsync();
            UsuarioPaginacion usuarioPaginacion = new UsuarioPaginacion();
            usuarioPaginacion.Number = numeroPagina;
            usuarioPaginacion.TotalPages = totalPaginas;
            List<UserInfo> usuarios = new List<UserInfo>();
            foreach(var item in users)
            {
                var userRoles = await userManager.GetRolesAsync(item);
                usuarios.Add(new UserInfo() 
                {
                    Id = item.Id, 
                    UserName = item.UserName, 
                    NormalizedUserName = item.NormalizedUserName, 
                    Email = item.Email, 
                    Password = item.PasswordHash, roles = userRoles
                });
            }
            if(numeroPagina == 0)
            {
                usuarioPaginacion.First = true; 
            } 
            else if(numeroPagina >= (totalPaginas - 1))
            {
                usuarioPaginacion.Last = true;
            }
            usuarioPaginacion.Content = usuarios;
            return usuarioPaginacion;            
        }


        [HttpGet("search/{id}",Name = "GetUsuario")]
        public async Task<ActionResult<UserInfo>> Get(string id)
        {
            var usuario = await userManager.FindByIdAsync(id);
            if(usuario != null ){
                return new UserInfo(){Id = usuario.Id, UserName = usuario.UserName, 
                    NormalizedUserName = usuario.NormalizedUserName, Email = usuario.Email, Password = usuario.PasswordHash};
            }
            else
            {
                return NotFound();
            }
        }

        [HttpPut("{id}")]
        public async Task<ActionResult> Put(string id, [FromBody] UserInfo userInfo){
            var usuario = await userManager.FindByIdAsync(id);            
            usuario.UserName = userInfo.UserName;
            usuario.NormalizedUserName = userInfo.NormalizedUserName;
            usuario.Email = userInfo.Email;                       
            if(usuario != null)
            {
                await userManager.UpdateAsync(usuario);
                await userManager.ChangePasswordAsync(usuario,usuario.PasswordHash,userInfo.Password);
                return NoContent();
            }
            else
            {
                return NotFound();
            }
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult<UserInfo>> Delete(string id){
            var usuario = await userManager.FindByIdAsync(id);
            var resuesta = await userManager.DeleteAsync(usuario);            
            return new UserInfo(){Id = usuario.Id, UserName = usuario.UserName, 
            NormalizedUserName = usuario.NormalizedUserName, Email = usuario.Email, Password = usuario.PasswordHash};
        }

        [HttpPost("AsignarUsuarioRol")]
        public async Task<ActionResult> AsignarRolUsuario([FromBody] UserRol userRol)
        {
            var usuario = await userManager.FindByIdAsync(userRol.UserId);
            if (usuario == null)
            {
                return NotFound();
            }
            await userManager.AddClaimAsync(usuario, new Claim(ClaimTypes.Role, userRol.RolName));
            await userManager.AddToRoleAsync(usuario, userRol.RolName);
            return Ok();
        }

        [HttpPost("RemoverUsuarioRol")]
        public async Task<ActionResult> RemoverRolUsuario([FromBody] UserRol userRol)
        {
            var usuario = await userManager.FindByIdAsync(userRol.UserId);
            if (usuario == null)
            {
                return NotFound();
            }
            await userManager.RemoveClaimAsync(usuario, new Claim(ClaimTypes.Role, userRol.RolName));
            await userManager.RemoveFromRoleAsync(usuario, userRol.RolName);
            return Ok();
        }
    }
}