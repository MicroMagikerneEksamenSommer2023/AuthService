using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class TestController : ControllerBase
{
    //Field til at logge informationer med.
    private readonly ILogger<TestController> _logger;

    // Field til at hente konfigurationsdata fra.
    private readonly IConfiguration _config;

    //Denne metode kræver, at anmodninger til ruten autoriseres ved hjælp af en gyldig JWT-token.
    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        return Ok("You're authorized");
    }
    
    public TestController(ILogger<TestController> logger, IConfiguration config)
    {
        // Tildeler IConfiguration-feltet den angivne konfiguration.
        _config = config;

        // Tildeler ILogger-feltet den angivne logger.
        _logger = logger;
    }
}