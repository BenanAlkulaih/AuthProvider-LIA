using AuthProvider.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AuthProvider.Data
{
    public static class DbInitializer
    {
        public static async Task InitializeAsync(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var services = scope.ServiceProvider;

            var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            var logger = services.GetRequiredService<ILogger<Program>>();

            try
            {
                // Delete all existing users.
                var existingUsers = await userManager.Users.ToListAsync();
                foreach (var user in existingUsers)
                {
                    var deleteResult = await userManager.DeleteAsync(user);
                    if (!deleteResult.Succeeded)
                    {
                        logger.LogError("Failed to delete user {Email}: {Errors}",
                            user.Email,
                            string.Join(", ", deleteResult.Errors.Select(e => e.Description)));
                    }
                }

                // Define the roles your app uses.
                var roles = new[] { "SuperAdmin", "Admin", "Teacher", "Student" };
                foreach (var role in roles)
                {
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        var roleResult = await roleManager.CreateAsync(new IdentityRole(role));
                        if (!roleResult.Succeeded)
                        {
                            logger.LogError("Error creating role {Role}: {Errors}",
                                role,
                                string.Join(", ", roleResult.Errors.Select(e => e.Description)));
                        }
                        else
                        {
                            logger.LogInformation("Role {Role} created successfully.", role);
                        }
                    }
                }

                // Define new users (they will be reinitialized as active).
                var users = new[]
                {
                    new
                    {
                        FullName = "Super Admin User",
                        Email = "superadmin@example.com",
                        PhoneNumber = "1234567890",
                        Birthday = new DateTime(1990, 1, 1),
                        Password = "SuperAdminPassword1",
                        SchoolId = 0,
                        Roles = new [] { "SuperAdmin" }
                    },
                    new
                    {
                        FullName = "Admin User",
                        Email = "admin@example.com",
                        PhoneNumber = "2345678901",
                        Birthday = new DateTime(1992, 5, 15),
                        Password = "AdminPassword1",
                        SchoolId = 1,
                        Roles = new [] { "Admin" }
                    },
                    new
                    {
                        FullName = "Teacher User",
                        Email = "teacher@example.com",
                        PhoneNumber = "3456789012",
                        Birthday = new DateTime(1985, 8, 20),
                        Password = "TeacherPassword1",
                        SchoolId = 1,
                        Roles = new [] { "Teacher" }
                    },
                    new
                    {
                        FullName = "Student User",
                        Email = "student@example.com",
                        PhoneNumber = "4567890123",
                        Birthday = new DateTime(2000, 11, 10),
                        Password = "StudentPassword1",
                        SchoolId = 1,
                        Roles = new [] { "Student" }
                    },
                };

                foreach (var u in users)
                {
                    // Check if the user already exists (should be none after deletion, but for safety).
                    var user = await userManager.FindByEmailAsync(u.Email);
                    if (user == null)
                    {
                        user = new ApplicationUser
                        {
                            UserName = u.Email,
                            Email = u.Email,
                            FullName = u.FullName,
                            PhoneNumber = u.PhoneNumber,
                            Birthday = u.Birthday,
                            SchoolId = u.SchoolId,
                            IsActive = true 
                        };

                        var result = await userManager.CreateAsync(user, u.Password);
                        if (result.Succeeded)
                        {
                            var roleResult = await userManager.AddToRolesAsync(user, u.Roles);
                            if (!roleResult.Succeeded)
                            {
                                foreach (var error in roleResult.Errors)
                                {
                                    logger.LogError("Error assigning role(s) to {Email}: Code={Code}, Description={Description}",
                                        u.Email, error.Code, error.Description);
                                }
                            }
                            else
                            {
                                logger.LogInformation("Roles {Roles} successfully assigned to {Email}",
                                    string.Join(", ", u.Roles), u.Email);
                            }
                        }
                        else
                        {
                            foreach (var error in result.Errors)
                            {
                                logger.LogError("Error creating user {Email}: Code={Code}, Description={Description}",
                                    u.Email, error.Code, error.Description);
                            }
                        }
                    }
                    else
                    {
                        logger.LogInformation("User {Email} already exists.", u.Email);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
    }
}
