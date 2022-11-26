using System.Linq;
using System.Net.WebSockets;
//using Internal;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using KalumAutenticacion.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace KalumAutenticacion.Controllers
{
    [Route("KalumAutenticacion/v1/[controller]")]
    [ApiController]
    public class CuentasController : ControllerBase
    {
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IConfiguration configuration;
        public CuentasController(IConfiguration configuration, 
            SignInManager<ApplicationUser> signInManager, 
            UserManager<ApplicationUser> userManager)
        {
            this.configuration = configuration;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        [HttpPost("Crear")]
        public async Task<ActionResult<UserToken>> Create([FromBody] UserInfo value)
        {
            var userInfo = new ApplicationUser { UserName = value.Email, Email = value.Email};
            var result = await userManager.CreateAsync(userInfo,value.Password);            
            if(result.Succeeded)
            {
                var usuario = await userManager.FindByIdAsync(userInfo.Id);                
                await userManager.AddToRoleAsync(userInfo, value.Roles.ElementAt(0));                
                return Buildtoken(usuario, value.Roles != null ? value.Roles : new List<String>());
            }
            else
            {
                return BadRequest("Username o password son invalidos");
            }
        }
        [HttpPost("Login")]
        public async Task<ActionResult<UserToken>> Login([FromBody] UserInfo value)
        {
            var result = await signInManager.PasswordSignInAsync(value.Email,value.Password,
                isPersistent:false,lockoutOnFailure:false);
            if(result.Succeeded){
                var usuario = await userManager.FindByEmailAsync(value.Email);
                var roles = await userManager.GetRolesAsync(usuario);
                return Buildtoken(usuario,roles);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "El login es invalido");
                return BadRequest(ModelState);
            }    
        }

        private UserToken Buildtoken(ApplicationUser userInfo, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, userInfo.Email),
                new Claim("api","kalum"),
                new Claim("username",userInfo.NormalizedUserName),
                new Claim("email", userInfo.Email),
                //new Claim("Apellidos","Tumax Chaclan"),
                //new Claim("Nombres","Edwin Rolando"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())                
            };
            foreach(var rol in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role,rol));
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:key"]));
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);  
            var expiration = DateTime.UtcNow.AddHours(1);
            JwtSecurityToken token = new JwtSecurityToken(
                issuer : null,
                audience : null,
                claims: claims,
                expires : expiration,
                signingCredentials: creds
            );
            return new UserToken(){
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration
            };
        }
    }
}