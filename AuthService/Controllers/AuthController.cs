using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using AuthService.Services;
using AuthService.Models;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

namespace AuthService.Controllers
{
    // Angiver at klassen er en controller for en API og aktiverer automatisk validering af anmodninger:
    [ApiController]
    [Route("authservice/v1")]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;

        private readonly IConfiguration _config;
        private readonly ILoginService _loginService;
       
  
        // Konstruktør, der tager en logger og en konfiguration som argumenter:
        public AuthController(ILogger<AuthController> logger, IConfiguration config, ILoginService loginService)
        {
            _logger = logger;
            _config = config; 
            _loginService = loginService;
        }

        // Angiver, at denne metode kan tilgås uden autentifikation:
        [AllowAnonymous]
        // Håndterer HTTP POST-anmodninger til "/authservice/v1/login" og tager imod en LoginInfo som parameter:
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginInfo login)
        {
            try
            {
                _logger.LogInformation("Login metode ramt, dette er dine login oplysinger:" + login.Email + login.AccessCode);
                // Kalder Login-metoden på LoginService og returnerer resultatet:   
                return await _loginService.Login(login);
            }
            catch (Exception ex)
            {
                // Hvis der opstår en fejl, logges den og kastes som en undtagelse:
                _loginService._logger.LogError($"Fejl ved login metode: {ex.Message}");
                throw;
            }
        }

        [Authorize]
        [HttpGet("gateway")]
        public async Task<IActionResult> NginxAuth()
        {
        return Ok("You're authorized");
        }
       
        [AllowAnonymous]
        // Håndterer HTTP POST-anmodninger til "/authservice/v1/validate" og tager imod en token-streng som parameter:
        [HttpPost("validate")]
        public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
        {
            try
            {
                // Kalder ValidateJwtToken-metoden på LoginService og returnerer resultatet:
                return await _loginService.ValidateJwtToken(token);
            }
            catch (Exception ex) 
            {
               // Hvis der opstår en fejl, logges den og returneres en HTTP-fejlstatus:
                _logger.LogError(ex, ex.Message);
                return StatusCode(404);
            }
        }

       
        [HttpGet("version")]
        public IEnumerable<string> Get()
        {
            var properties = new List<string>();
            var assembly = typeof(Program).Assembly; 

            // Henter metadata om assembly'en og tilføjer dem til en liste:
            foreach (var attribute in assembly.GetCustomAttributesData()) 
            {
                properties.Add($"{attribute.AttributeType.Name} - {attribute.ToString()}"); 
            }

            // Logger information om assembly-metadataen:
            _logger.LogInformation($"Hentet assembly-metadata for version: {properties}");
            
            // Returnerer listen med assembly-metadata:
            return properties; 
        }
    }
}