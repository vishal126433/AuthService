using AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

public static class JwtHelper
{

    public static string GenerateAccessToken(User user, IConfiguration config)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user), "User cannot be null");

        string roleName = string.IsNullOrWhiteSpace(user.Role) ? "User" : user.Role;

        var authClaims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, roleName) // This will be used by [Authorize(Roles = "Admin")]
    };

    


        var secretKey = config["JwtSettings:SecretKey"];
        var issuer = config["JwtSettings:Issuer"];
        var audience = config["JwtSettings:Audience"];

        if (string.IsNullOrWhiteSpace(secretKey))
            throw new ArgumentNullException("JwtSettings:SecretKey", "JWT SecretKey is missing in configuration.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
    issuer: issuer,
    audience: audience,
    claims: authClaims,
    expires: DateTime.UtcNow.AddMinutes(30),
    signingCredentials: creds
 );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }



    public static string GenerateRefreshToken(User user, IConfiguration config)
    {
        if (user == null)
            throw new ArgumentNullException(nameof(user), "User cannot be null");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
        };

        var secretKey = config["JwtSettings:SecretKey"];
        var issuer = config["JwtSettings:Issuer"];
        var audience = config["JwtSettings:Audience"];

        if (string.IsNullOrWhiteSpace(secretKey))
            throw new ArgumentNullException("JwtSettings:SecretKey", "JWT SecretKey is missing in configuration.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(30),

            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
