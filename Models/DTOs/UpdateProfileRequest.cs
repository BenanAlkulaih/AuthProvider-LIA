﻿namespace AuthProvider.Models.DTOs
{
    public class UpdateProfileRequest
    {
        public string FullName { get; set; } = null!;
        public DateTime Birthday { get; set; }
        public string PhoneNumber { get; set; } = null!;
        public string? Address { get; set; }
        public bool IsActive { get; set; }

        public string[] Roles { get; set; } = null!;
    }
}
