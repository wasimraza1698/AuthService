using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AuthService.Data;
using AuthService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(UserController));
        private readonly AuthDbContext _context;
        private readonly IConfiguration _config;

        public UserController(AuthDbContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }
        [HttpPost("User")]
        public User GetUser(User valuser)
        {
            var user = _context.Users.FirstOrDefault(c => c.UserName == valuser.UserName && c.Password == valuser.Password);
            if (user == null)
            {
                return null;
            }
            return user;
        }
        [HttpPost("Login")]
        public IActionResult Login([FromBody] User login)
        {

            _log4net.Info("Authentication initiated for UserId " + login.UserID.ToString());
            IActionResult response = Unauthorized();
            User user = GetUser(login);
            if (user == null)
            {
                return NotFound();
            }
            else
            {
                var tokenString = GenerateJSONWebToken(login);
                response = Ok(new { token = tokenString });
                return response;
            }
        }
        private string GenerateJSONWebToken(User user)
        {
            _log4net.Info("Token Generation initiated for UserId " + user.UserID.ToString());
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jet:Issuer"],
                null,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token).ToString();
        }
    }


}

