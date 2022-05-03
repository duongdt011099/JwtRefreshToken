using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using test.Models;
using test.Services;

namespace test.Controllers;

[Authorize]
[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    private IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public IActionResult Authenticate([FromBody] AuthenticateRequest model)
    {
        var response = _userService.Authenticate(model, ipAddress());

        if (response == null)
            return BadRequest(new { message = "Username or password is incorrect" });

        setTokenCookie(response.RefreshToken);

        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("seed")]
    public IActionResult SeedData()
    {
        _userService.SeedData();
        return Ok();
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _userService.RefreshToken(refreshToken, ipAddress());

        if (response == null)
            return Unauthorized(new { message = "Invalid token" });

        setTokenCookie(response.RefreshToken);

        return Ok(response);
    }

    [HttpPost("revoke-token")]
    public IActionResult RevokeToken([FromBody] RevokeTokenRequest model)
    {
        // accept token from request body or cookie
        var token = model.Token ?? Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required" });

        var response = _userService.RevokeToken(token, ipAddress());

        if (!response)
            return NotFound(new { message = "Token not found" });

        return Ok(new { message = "Token revoked" });
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var users = _userService.GetAll();
        return Ok(users);
    }

    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var user = _userService.GetById(id);
        if (user == null) return NotFound();

        return Ok(user);
    }

    [HttpGet("{id}/refresh-tokens")]
    public IActionResult GetRefreshTokens(int id)
    {
        var user = _userService.GetById(id);
        if (user == null) return NotFound();

        return Ok(user.RefreshTokens);
    }

    // helper methods

    private void setTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
}