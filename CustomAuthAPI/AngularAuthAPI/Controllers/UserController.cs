using AngularAuthAPI.Context;
using AngularAuthAPI.Models;
using AngularAuthAPI.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private AppDbContext _context;
      
        public UserController(AppDbContext db)
        {
            _context = db;
           
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User user)
        {
            if (user == null)
                return BadRequest();
            var retrievedUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == user.Username );
            if (retrievedUser == null)
                return NotFound(new { Message = "User Not Found !" });
            if (!PasswordHasher.VerifyPassword(user.Password, retrievedUser.Password))
                return BadRequest(new { Massage = "Incorrect Password" });
            retrievedUser.Token = CreateJwt(retrievedUser);
            return Ok(new
            {
               Token= retrievedUser.Token,
                Message = "Login Successfully!"
            });
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User newUser)
        {
            
            if (newUser == null)
                return BadRequest();
            if (await CheckEmailAsync(newUser.Email))
                return BadRequest(new { Message = "Email Already Exist!" });
            if (await CheckUserNameAsync(newUser.Username))
                return BadRequest(new { Message = "Username is taken " });
            var pass = CheckPasswordWeakness(newUser.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass });

            newUser.Password=PasswordHasher.HashPassword(newUser.Password);
            newUser.Role = "User";
            newUser.Token = "";
            await _context.Users.AddAsync(newUser);
            await _context.SaveChangesAsync();
            return Ok(new
            {
                Message="Signed Up Successfully"
            });
        }
        [Authorize, HttpGet] //testing auth
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _context.Users.ToListAsync());
        }
        private async Task<bool> CheckUserNameAsync(string userName)
        {
            var model = await _context.Users.AnyAsync(x => x.Username == userName);
            return model;
        }
        private async Task<bool> CheckEmailAsync(string email)
        {
            var model = await _context.Users.AnyAsync(x => x.Email == email);
            return model;
        }
        private string CheckPasswordWeakness(string password)
        {
            StringBuilder stringBuilder = new StringBuilder();
            if (password.Length < 8)
                stringBuilder.Append("Minmum Characters must be 8" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]"))
                stringBuilder.Append("Password must contain Captial Letters and Numbers!" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,~,#,$,%,^,&,*,+,//,/,;,:,']"))
                stringBuilder.Append("Password must contain Special Characters!" + Environment.NewLine);
            return stringBuilder.ToString();
        }
        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryveryverysecret....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")

            });
            var credientials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credientials
            };
            var token=jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }
      
    }
}
