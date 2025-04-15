using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthProvider.Models;
using AuthProvider.Models.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers
{
    [Route("account")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<ApplicationUser> userManager,
                                 SignInManager<ApplicationUser> signInManager,
                                 IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Unauthorized(new { error = "Invalid email or password" });

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!result.Succeeded)
                return Unauthorized(new { error = "Invalid email or password" });

            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
                {
                    new Claim("id", user.Id),
                    new Claim(ClaimTypes.Email, user.Email!),
                    new Claim("fullName", user.FullName ?? ""),
                    new Claim("schoolId", user.SchoolId.ToString())
                };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"] ?? "");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                                                            SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return Ok(new { token = tokenString });
        }

        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetMe()
        {
            var userIdClaim = User.FindFirst("id")?.Value;
            if (userIdClaim == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userIdClaim);
            if (user == null)
                return NotFound();

            // Retrieve roles assigned to the user.
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                id = user.Id,
                fullName = user.FullName,
                roles,
                phoneNumber = user.PhoneNumber,
                email = user.Email,
                birthday = user.Birthday,
                address = user.Address,
                schoolId = user.SchoolId
            });
        }

        [Authorize]
        [HttpPut("update")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            // Retrieve user id from the token claims.
            var userId = User.FindFirst("id")?.Value;
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            // Update the user's properties.
            user.FullName = model.FullName;
            user.Birthday = model.Birthday;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address; 

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new
            {
                message = "Profile updated successfully.",
                user = new
                {
                    user.Id,
                    user.FullName,
                    user.Email,
                    user.Birthday,
                    user.PhoneNumber,
                    user.Address,
                    user.SchoolId
                }
            });
        }
    }
}
