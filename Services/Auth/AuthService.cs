
using AuthService.Data;
using AuthService.DTOs;
using AuthService.Helpers;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services.Auth
{
    public class AuthService : IAuthService
    {
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public AuthService(AuthDbContext db, IConfiguration config)
        {
            _db = db;
            _config = config;
        }

        public async Task<string> RegisterAsync(RegisterRequest req)
        {
            var existingUser = await _db.Users
                .FirstOrDefaultAsync(u => u.Username == req.Username || u.Email == req.Email);

            if (existingUser != null)
                return "Username or Email already exists";

            var user = new User
            {
                Username = req.Username,
                Email = req.Email
            };

            var passwordHasher = new PasswordHasher<User>();
            user.PasswordHash = passwordHasher.HashPassword(user, req.Password);

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return "User Registered Successfully";
        }

        public async Task<string> ChangePasswordAsync(ChangePasswordRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.OldPassword) ||
                string.IsNullOrWhiteSpace(request.NewPassword))
                return "Username, old password, and new password are required.";

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
                return "User not found";

            var passwordHasher = new PasswordHasher<User>();
            var verifyResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.OldPassword);

            if (verifyResult == PasswordVerificationResult.Failed)
                return "Old password is incorrect";

            if (request.OldPassword == request.NewPassword)
                return "New password cannot be the same as the old password";

            user.PasswordHash = passwordHasher.HashPassword(user, request.NewPassword);
            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            return "Password changed successfully";
        }

        public TokenResponse Login(LoginRequest req)
        {
            var user = _db.Users.FirstOrDefault(u => u.Email == req.Email);
            if (user == null)
                throw new UnauthorizedAccessException("Invalid email or password.");

            if (!user.IsActive)
                throw new UnauthorizedAccessException("This user is inactive. Please contact the administrator.");

            var passwordHasher = new PasswordHasher<User>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
            if (result == PasswordVerificationResult.Failed)
                throw new UnauthorizedAccessException("Invalid email or password.");

            var accessToken = JwtHelper.GenerateAccessToken(user, _config);
            var refreshToken = JwtHelper.GenerateRefreshToken(user, _config);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }




        public TokenResponse? RefreshToken(string refreshToken)
        {
            if (string.IsNullOrEmpty(refreshToken)) return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]);

            try
            {
                var principal = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = _config["JwtSettings:Issuer"],
                    ValidAudience = _config["JwtSettings:Audience"],
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
                             principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

                var user = _db.Users.FirstOrDefault(u => u.Id.ToString() == userId);
                if (user == null) return null;

                var newAccessToken = JwtHelper.GenerateAccessToken(user, _config);
                return new TokenResponse { AccessToken = newAccessToken };
            }
            catch
            {
                return null;
            }
        }
    }
}
