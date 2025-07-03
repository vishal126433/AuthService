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
using AuthService.Helpers;
using Microsoft.AspNetCore.Identity;
using AuthService.DTOs;
using AuthService.Services.Auth;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest req)
    {
        var result = await _authService.RegisterAsync(req);
        if (result == "User Registered Successfully")
            return Ok(result);
        return BadRequest(result);
    }

    [HttpPut("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest req)
    {
        var result = await _authService.ChangePasswordAsync(req);
        if (result == "Password changed successfully")
            return Ok(result);
        return BadRequest(result);
    }

    [HttpPost("login")]
    public IActionResult Login(LoginRequest req)
    {
        try
        {
            var tokenResponse = _authService.Login(req);
            CookieHelper.AppendRefreshToken(Response, tokenResponse.RefreshToken!);
            return Ok(new { accessToken = tokenResponse.AccessToken });
        }
        catch (UnauthorizedAccessException ex)
        {
            // Return HTTP 401 + message
            return Unauthorized(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            // For unexpected server errors
            return StatusCode(500, new { message = "An unexpected error occurred." });
        }
    }


    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var newToken = _authService.RefreshToken(refreshToken ?? "");
        if (newToken == null)
            return Unauthorized("Invalid or expired refresh token");

        return Ok(new TokenResponse { AccessToken = newToken.AccessToken });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        CookieHelper.DeleteRefreshToken(Response);
        return Ok("Logged out successfully");
    }
}
