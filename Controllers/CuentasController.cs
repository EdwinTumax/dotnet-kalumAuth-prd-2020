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
                return Buildtoken(value,new List<String>());
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
                return Buildtoken(value,roles);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "El login es invalido");
                return BadRequest(ModelState);
            }    
        }

        private UserToken Buildtoken(UserInfo userInfo, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, userInfo.Email),
                new Claim("api","kalum"),
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