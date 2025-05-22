using AuthService.Models;
using Microsoft.AspNetCore.Mvc;
using AuthService.Data;
using Microsoft.AspNetCore.Identity.Data;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthDbContext _db;
    private readonly IConfiguration _config;

    public AuthController(AuthDbContext db, IConfiguration config)
    {
        _db = db;
        _config = config;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest req)
    {
        // Check if username or email already exists
        var existingUser = await _db.Users
            .FirstOrDefaultAsync(u => u.Username == req.Username || u.Email == req.Email);

        if (existingUser != null)
        {
            return BadRequest("Username or Email already exists");
        }

        // Proceed to register the user
        var user = new User
        {
            Username = req.Username,
            Email = req.Email,
            PasswordHash = req.Password
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return Ok("User Registered Successfully");
    }


    [HttpPost("login")]
    public IActionResult Login(LoginRequest req)
    {
        var user = _db.Users.FirstOrDefault(u => u.Email == req.Email);

        if (user == null || user.PasswordHash != req.Password)
            return Unauthorized("Invalid credentials");

        var accessToken = JwtHelper.GenerateAccessToken(user, _config);
        var refreshToken = JwtHelper.GenerateRefreshToken(user, _config);

        // Set refresh token as HttpOnly cookie
        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTime.UtcNow.AddDays(7)
        });

        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
            Role = user.Role
        });
    }
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken))
            return Unauthorized("No refresh token found");

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
            if (user == null)
                return Unauthorized("User not found");

            var newAccessToken = JwtHelper.GenerateAccessToken(user, _config);
            var newRefreshToken = JwtHelper.GenerateRefreshToken(user, _config);

            // Replace cookie
            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddDays(7)
            });

            return Ok(new TokenResponse { AccessToken = newAccessToken });
        }
        catch
        {
            return Unauthorized("Invalid or expired refresh token");
        }
    }



    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("refreshToken", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/"
        });

        return Ok("Logged out successfully");
    }











}
