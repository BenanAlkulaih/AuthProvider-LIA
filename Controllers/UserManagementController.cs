using AuthProvider.Models;
using AuthProvider.Models.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthProvider.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserManagementController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserManagementController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        /// Gets all users for a given school.
        [HttpGet("bySchool/{schoolId}")]
        
        public async Task<IActionResult> GetUsersBySchool(int schoolId)
        {
            // Query users based on schoolId
            var users = await _userManager.Users
                            .Where(u => u.SchoolId == schoolId)
                            .ToListAsync();

            // Create a DTO list including the user's roles
            var userDtos = new List<object>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDtos.Add(new
                {
                    user.Id,
                    user.FullName,
                    user.Email,
                    user.Birthday,
                    user.PhoneNumber,
                    user.SchoolId,
                    user.IsActive,
                    Roles = roles
                });
            }

            return Ok(userDtos);
        }

        // Only SuperAdmin can create a new SuperAdmin.
        [Authorize(Roles = "SuperAdmin")]
        [HttpPost("create-superadmin")]
        public async Task<IActionResult> CreateSuperAdmin([FromBody] RegisterRequest model)
        {
            model.Roles = new[] { "SuperAdmin" };
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName,
                Birthday = model.Birthday,
                PhoneNumber = model.PhoneNumber,
                SchoolId = 0,  // SuperAdmin accounts are not tied to a specific school.
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRolesAsync(user, model.Roles);
            return Ok(new { message = "SuperAdmin created successfully" });
        }

        // Only SuperAdmin can create a new Admin.
        [Authorize(Roles = "SuperAdmin")]
        [HttpPost("create-admin")]
        public async Task<IActionResult> CreateAdmin([FromBody] RegisterRequest model)
        {
            // For admin creation, a valid schoolId must be provided.
            if (model.SchoolId <= 0)
                return BadRequest("A valid schoolId must be provided.");

            model.Roles = new[] { "Admin" };
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName,
                Birthday = model.Birthday,
                PhoneNumber = model.PhoneNumber,
                SchoolId = model.SchoolId,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRolesAsync(user, model.Roles);
            return Ok(new { message = "Admin created successfully" });
        }

        // Accessible by SuperAdmin and Admin – allowed to create Teacher users.
        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("create-teacher")]
        public async Task<IActionResult> CreateTeacher([FromBody] RegisterRequest model)
        {
            if (model.SchoolId <= 0)
                return BadRequest("A valid schoolId must be provided.");

            // If the current user is an Admin, check that the schoolId matches their own.
            if (User.IsInRole("Admin"))
            {
                var currentSchoolIdStr = User.FindFirst("schoolId")?.Value;
                if (!int.TryParse(currentSchoolIdStr, out int currentSchoolId))
                {
                    return BadRequest("Invalid school information in user token.");
                }
                if (model.SchoolId != currentSchoolId)
                {
                    return Forbid("Admins can only create users for their own school.");
                }
            }

            model.Roles = new[] { "Teacher" };
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName,
                Birthday = model.Birthday,
                PhoneNumber = model.PhoneNumber,
                SchoolId = model.SchoolId,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRolesAsync(user, model.Roles);
            return Ok(new { message = "Teacher created successfully" });
        }

        // Accessible by SuperAdmin, Admin, and Teacher – allowed to create Student users.
        [Authorize(Roles = "SuperAdmin,Admin,Teacher")]
        [HttpPost("create-student")]
        public async Task<IActionResult> CreateStudent([FromBody] RegisterRequest model)
        {
            if (model.SchoolId <= 0)
                return BadRequest("A valid schoolId must be provided.");

            // For Admins or Teachers, verify that they can only create users for their own school.
            if (User.IsInRole("Admin") || User.IsInRole("Teacher"))
            {
                var currentSchoolIdStr = User.FindFirst("schoolId")?.Value;
                if (!int.TryParse(currentSchoolIdStr, out int currentSchoolId))
                {
                    return BadRequest("Invalid school information in user token.");
                }
                if (model.SchoolId != currentSchoolId)
                {
                    return Forbid("You can only create users for your own school.");
                }
            }

            model.Roles = new[] { "Student" };
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName,
                Birthday = model.Birthday,
                PhoneNumber = model.PhoneNumber,
                SchoolId = model.SchoolId,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            await _userManager.AddToRolesAsync(user, model.Roles);
            return Ok(new { message = "Student created successfully" });
        }
    }
}
