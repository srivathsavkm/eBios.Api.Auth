using eBios.Api.Auth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace eBios.Api.Auth.Controllers
{
    [Route("api/token")]
    [ApiController]
    [AllowAnonymous] // This allows unauthenticated access to the token generation endpoint
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("generate")]
        public IActionResult GenerateToken([FromBody] TokenRequestModel model)
        {
            if (IsValidUser(model.UserName, model.Password))
            {
                var token = GenerateJwtToken(model.UserName);

                return Ok(new { Token = token });
            }
            return Unauthorized("Invalid credentials");
        }

        private string GenerateJwtToken(string userName)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, userName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(token);

        }
        private bool IsValidUser(string userName, string password)
        {
            if (string.IsNullOrEmpty(userName))
                return false;

            if (string.IsNullOrEmpty(password))
                return false;

            //Validate from DB
            if (userName == "root" && password == "root")
                return true;

            return false;
        }
    }
}
