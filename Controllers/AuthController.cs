﻿using AuthService.Models;
using Microsoft.AspNetCore.Mvc;
using AuthService.Data;
using Microsoft.AspNetCore.Identity.Data;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using AuthService.Helpers;
using Microsoft.AspNetCore.Identity;

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
        var existingUser = await _db.Users
            .FirstOrDefaultAsync(u => u.Username == req.Username || u.Email == req.Email);

        if (existingUser != null)
            return BadRequest("Username or Email already exists");

        var user = new User
        {
            Username = req.Username,
            Email = req.Email
        };

        var passwordHasher = new PasswordHasher<User>();
        user.PasswordHash = passwordHasher.HashPassword(user, req.Password);

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return Ok("User Registered Successfully");
    }


    [HttpPost("login")]
    public IActionResult Login(LoginRequest req)
    {
        var user = _db.Users.FirstOrDefault(u => u.Email == req.Email);
        if (user == null)
            return Unauthorized("Invalid credentials");

        var passwordHasher = new PasswordHasher<User>();
        var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);

        if (result == PasswordVerificationResult.Failed)
            return Unauthorized("Invalid credentials");

        var accessToken = JwtHelper.GenerateAccessToken(user, _config);
        var refreshToken = JwtHelper.GenerateRefreshToken(user, _config);

        CookieHelper.AppendRefreshToken(Response, refreshToken);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
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
        CookieHelper.DeleteRefreshToken(Response); //  Moved to helper
        return Ok("Logged out successfully");
    }
}
