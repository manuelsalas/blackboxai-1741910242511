using AuthApi.Models;

namespace AuthApi.Services;

public interface ITokenService
{
    AuthResponse CreateToken(User user);
    string? ValidateToken(string token);
    string GenerateRefreshToken();
}
