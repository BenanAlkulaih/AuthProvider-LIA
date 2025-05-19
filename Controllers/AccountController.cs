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
                schoolId = user.SchoolId,
                isActive = user.IsActive 
            });
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpGet("{userId}")]
        public async Task<IActionResult> GetUserById(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

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
                schoolId = user.SchoolId,
                isActive = user.IsActive
            });
        }

        [Authorize]
        [HttpPut("update")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var userId = User.FindFirst("id")?.Value;
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            user.FullName = model.FullName;
            user.Birthday = model.Birthday;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return BadRequest(updateResult.Errors);

            if (model.Roles != null)
            {
                var currentRoles = await _userManager.GetRolesAsync(user);
                if (currentRoles.Any())
                {
                    var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                    if (!removeResult.Succeeded)
                        return BadRequest(new { error = "Failed to remove old roles", details = removeResult.Errors });
                }
                if (model.Roles.Any())
                {
                    var addResult = await _userManager.AddToRolesAsync(user, model.Roles);
                    if (!addResult.Succeeded)
                        return BadRequest(new { error = "Failed to add new roles", details = addResult.Errors });
                }
            }
            var finalRoles = await _userManager.GetRolesAsync(user);
            return Ok(new
            {
                message = "Profile updated successfully.",
                user = new
                {
                    user.Id,
                    user.FullName,
                    roles = finalRoles,
                    user.Email,
                    user.Birthday,
                    user.PhoneNumber,
                    user.Address,
                    user.SchoolId,
                    user.IsActive
                }
            });
        }


        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpPut("{userId}")]
        public async Task<IActionResult> UpdateUserById(string userId, [FromBody] UpdateProfileRequest model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            user.FullName = model.FullName;
            user.Birthday = model.Birthday;
            user.PhoneNumber = model.PhoneNumber;
            user.Address = model.Address;

            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
                return BadRequest(updateResult.Errors);

            if (model.Roles != null)
            {
                var currentRoles = await _userManager.GetRolesAsync(user);
                if (currentRoles.Any())
                {
                    var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                    if (!removeResult.Succeeded)
                        return BadRequest(new { error = "Failed to remove old roles", details = removeResult.Errors });
                }

                if (model.Roles.Any())
                {
                    var addResult = await _userManager.AddToRolesAsync(user, model.Roles);
                    if (!addResult.Succeeded)
                        return BadRequest(new { error = "Failed to add new roles", details = addResult.Errors });
                }
            }

            var finalRoles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                message = "User updated successfully.",
                user = new
                {
                    user.Id,
                    user.FullName,
                    roles = finalRoles,
                    user.PhoneNumber,
                    user.Email,
                    user.Birthday,
                    user.Address,
                    user.SchoolId,
                    user.IsActive
                }
            });
        }


        #region Inactivation Endpoints (Soft Delete)

        // Self-Inactivate: The current user sets IsActive = false.
        [Authorize]
        [HttpDelete("inactivate")]
        public async Task<IActionResult> InactivateAccount()
        {
            var userId = User.FindFirst("id")?.Value;
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            user.IsActive = false;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to inactivate user", details = result.Errors });

            return Ok(new { message = "User account inactivated successfully" });
        }

        [Authorize]
        [HttpPost("reactivate")]
        public async Task<IActionResult> ReactivateAccount()
        {
            var userId = User.FindFirst("id")?.Value;
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            user.IsActive = true; // Mark user as active again.
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to reactivate user", details = result.Errors });

            return Ok(new { message = "User account reactivated successfully" });
        }

        // Admin Inactivate: Admin/ SuperAdmin can inactivate any user.
        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpDelete("inactivate/{userId}")]
        public async Task<IActionResult> InactivateUserByAdmin(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            user.IsActive = false;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to inactivate user", details = result.Errors });

            return Ok(new { message = "User account inactivated successfully" });
        }

        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpPost("reactivate/{userId}")]
        public async Task<IActionResult> ReactivateUserByAdmin(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            user.IsActive = true;
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to reactivate user", details = result.Errors });

            return Ok(new { message = "User account reactivated successfully" });
        }


        #endregion

        #region Full Deletion Endpoints (Permanent Delete)

        // Self-Delete: The current user completely removes their account.
        [Authorize]
        [HttpDelete("delete")]
        public async Task<IActionResult> FullDeleteAccount()
        {
            var userId = User.FindFirst("id")?.Value;
            if (userId == null)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to delete user", details = result.Errors });

            return Ok(new { message = "User account deleted successfully" });
        }

        // Admin Delete: Admin/ SuperAdmin can fully delete any user.
        [Authorize(Roles = "Admin,SuperAdmin")]
        [HttpDelete("delete/{userId}")]
        public async Task<IActionResult> FullDeleteUserByAdmin(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound(new { error = "User not found" });

            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
                return BadRequest(new { error = "Failed to delete user", details = result.Errors });

            return Ok(new { message = "User account deleted successfully" });
        }

        #endregion
    }
}
