using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthApi.Models;
using AuthApi.Services;
using System.Threading.Tasks;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IUserService userService, ILogger<AuthController> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest request)
    {
        try
        {
            _logger.LogInformation("Registration attempt for user: {Username}", request.Username);
            var response = await _userService.RegisterAsync(request);
            _logger.LogInformation("Registration successful for user: {Username}", request.Username);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Registration failed for user: {Username}", request.Username);
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed unexpectedly for user: {Username}", request.Username);
            return StatusCode(500, new { message = "An error occurred during registration" });
        }
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        try
        {
            _logger.LogInformation("Login attempt for user: {Username}", request.Username);
            var response = await _userService.LoginAsync(request);
            _logger.LogInformation("Login successful for user: {Username}", request.Username);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Login failed for user: {Username}", request.Username);
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login failed unexpectedly for user: {Username}", request.Username);
            return StatusCode(500, new { message = "An error occurred during login" });
        }
    }

    [HttpPost("refresh-token")]
    public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            _logger.LogInformation("Token refresh attempt");
            var response = await _userService.RefreshTokenAsync(request.Token, request.RefreshToken);
            _logger.LogInformation("Token refresh successful");
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Token refresh failed");
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh failed unexpectedly");
            return StatusCode(500, new { message = "An error occurred during token refresh" });
        }
    }

    [Authorize]
    [HttpGet("protected")]
    public ActionResult<object> Protected()
    {
        var username = User.Identity?.Name;
        _logger.LogInformation("Protected endpoint accessed by user: {Username}", username);
        return Ok(new { message = $"Hello {username}, this is a protected endpoint!" });
    }
}
