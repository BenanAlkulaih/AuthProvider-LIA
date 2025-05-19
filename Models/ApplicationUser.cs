using Microsoft.AspNetCore.Identity;

namespace AuthProvider.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; } = null!;
        public DateTime Birthday { get; set; }
        public int SchoolId { get; set; }
        public string? Address { get; set; }
        public bool IsActive { get; set; }
    }
}
