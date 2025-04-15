namespace AuthProvider.Models.DTOs
{
    public class RegisterRequest
    {
        public string Email { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
        public string FullName { get; set; } = null!;
        public DateTime Birthday { get; set; }
        public string PhoneNumber { get; set; } = null!;
        public int SchoolId { get; set; }
        public string[] Roles { get; set; } = null!;
    }
}
