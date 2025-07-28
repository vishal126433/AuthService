using AuthService.Data;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Interfaces;
using AuthService.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Services
{
    public class AuthService : IAuthService
    {
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthService> _logger;
        private readonly ITokenService _tokenService;


        public AuthService(AuthDbContext db, IConfiguration config, ILogger<AuthService> logger, ITokenService tokenService)

        {
            _db = db ?? throw new ArgumentNullException(nameof(db), "DbContext cannot be null.");
            _config = config ?? throw new ArgumentNullException(nameof(config), "Configuration cannot be null.");
            _logger = logger ?? throw new ArgumentNullException(nameof(logger), "Logger cannot be null.");
            _tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));

        }

        public async Task<string> RegisterAsync(RegisterRequest req)
        {
            _logger.LogInformation("Registering new user with username: {Username}", req.Username);

            var existingUser = await _db.Users
                .FirstOrDefaultAsync(u => u.Username == req.Username || u.Email == req.Email);

            if (existingUser != null)
            {
                _logger.LogWarning("Registration failed: Username or Email already exists.");
                return "Username or Email already exists";
            }

            var user = new User
            {
                Username = req.Username,
                Email = req.Email
            };

            var passwordHasher = new PasswordHasher<User>();
            user.PasswordHash = passwordHasher.HashPassword(user, req.Password);

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            _logger.LogInformation("User registered successfully with Id {UserId}", user.Id);
            return "User Registered Successfully";
        }

        public async Task<string> ChangePasswordAsync(ChangePasswordRequest request)
        {
            _logger.LogInformation("Changing password for user: {Username}", request.Username);

            if (string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.OldPassword) ||
                string.IsNullOrWhiteSpace(request.NewPassword))
            {
                _logger.LogWarning("Change password failed: required fields missing.");
                return "Username, old password, and new password are required.";
            }

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
            {
                _logger.LogWarning("Change password failed: user not found.");
                return "User not found";
            }

            var passwordHasher = new PasswordHasher<User>();
            var verifyResult = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.OldPassword);

            if (verifyResult == PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Change password failed: old password incorrect.");
                return "Old password is incorrect";
            }

            if (request.OldPassword == request.NewPassword)
            {
                _logger.LogWarning("Change password failed: new password same as old.");
                return "New password cannot be the same as the old password";
            }

            user.PasswordHash = passwordHasher.HashPassword(user, request.NewPassword);
            _db.Users.Update(user);
            await _db.SaveChangesAsync();

            _logger.LogInformation("Password changed successfully for user: {Username}", request.Username);
            return "Password changed successfully";
        }

        public TokenResponse Login(LoginRequest req)
        {
            _logger.LogInformation("Attempting login for email: {Email}", req.Email);

            var user = _db.Users.FirstOrDefault(u => u.Email == req.Email);
            if (user == null)
            {
                _logger.LogWarning("Login failed: invalid email.");
                throw new UnauthorizedAccessException("Invalid email or password.");
            }

            if (!user.IsActive)
            {
                _logger.LogWarning("Login failed: user {Email} is inactive.", req.Email);
                throw new UnauthorizedAccessException("This user is inactive. Please contact the administrator.");
            }

            var passwordHasher = new PasswordHasher<User>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Login failed: invalid password for email: {Email}", req.Email);
                throw new UnauthorizedAccessException("Invalid email or password.");
            }

            var accessToken = _tokenService.GenerateAccessToken(user);
            var refreshToken = _tokenService.GenerateRefreshToken(user);

            _logger.LogInformation("User logged in successfully: {Email}", req.Email);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }

        public TokenResponse? RefreshToken(string refreshToken)
        {
            _logger.LogInformation("Refreshing access token.");

            if (string.IsNullOrEmpty(refreshToken))
            {
                _logger.LogWarning("Refresh token failed: token is null or empty.");
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]);

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
            if (user == null)
            {
                _logger.LogWarning("Refresh token failed: user not found.");
                return null;
            }

            var newAccessToken = _tokenService.GenerateAccessToken(user);

            _logger.LogInformation("Access token refreshed successfully for user Id: {UserId}", user.Id);

            return new TokenResponse { AccessToken = newAccessToken };
        }
    }
}
