using System.Security.Claims;
using System.Threading.Tasks;
using KalumAutenticacion.Context;
using KalumAutenticacion.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace KalumAutenticacion.Controllers
{
    [Route("KalumAutenticacion/v1/[controller]")]
    [ApiController]
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