using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthService.Services;
using AuthService.Models;

namespace AuthService.Controllers
{
    // Angiver at klassen er en controller for en API og aktiverer automatisk validering af anmodninger:
    [ApiController]
    [Route("authservice/v1")]
    public class AuthController : ControllerBase
    {
        // Attributter
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

        [AllowAnonymous] // Angiver, at denne metode kan tilgås uden autentifikation
        [HttpPost("login")] // Håndterer HTTP POST-anmodninger til "/authservice/v1/login" og tager imod en LoginInfo som parameter
        public async Task<IActionResult> Login([FromBody] LoginInfo login)
        {
            try
            {
                _logger.LogInformation("Login metode ramt, dette er dine login oplysinger:" + login.Email + login.AccessCode);  
                return await _loginService.Login(login); // Kalder Login-metoden på LoginService og returnerer resultatet
            }
            catch (Exception ex)
            {
                _loginService._logger.LogError($"Fejl ved login metode: {ex.Message}"); // Hvis der opstår en fejl, logges den
                throw; // Kastes som en undtagelse
            }
        }

        [Authorize]
        [HttpGet("gateway")]
        public async Task<IActionResult> NginxAuth()
        {
            return Ok("You're authorized");
        }

        [AllowAnonymous]
        [HttpPost("validate")] // Håndterer HTTP POST-anmodninger til "/authservice/v1/validate" og tager imod en token-streng som parameter
        public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
        {
            try
            {
                return await _loginService.ValidateJwtToken(token); // Kalder ValidateJwtToken-metoden på LoginService og returnerer resultatet:
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message); // Hvis der opstår en fejl, logges den
                return StatusCode(404); // Returneres en HTTP-fejlstatus
            }
        }

        [HttpGet("version")]
        public IEnumerable<string> Get()
        {
            var properties = new List<string>();
            var assembly = typeof(Program).Assembly;

            foreach (var attribute in assembly.GetCustomAttributesData()) // Henter metadata om assembly'en og tilføjer dem til en liste
            {
                properties.Add($"{attribute.AttributeType.Name} - {attribute.ToString()}");
            }

            _logger.LogInformation($"Hentet assembly-metadata for version: {properties}"); // Logger information om assembly-metadataen

            return properties; // Returnerer listen med assembly-metadata
        }
    }
}