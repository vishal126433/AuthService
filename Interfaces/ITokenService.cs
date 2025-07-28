using AuthService.Models;

namespace AuthService.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken(User user);
    }
}
