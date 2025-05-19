using System.ComponentModel.DataAnnotations;

namespace AuthService.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        [MaxLength(100)]
        public string PasswordHash { get; set; }
        public string Role { get; set; } = "User"; // default role
        //public string? RefreshToken { get; set; }
        //public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}
