using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using AuthService.Services;


namespace AuthService.Controllers
{
    // En API-controller, der håndterer godkendelses- og login-processen for kunder.
    [ApiController]
    [Route("[AuthService]")]
    public class AuthController : ControllerBase
    {
        private readonly LoginService _loginService;
        private readonly CustomerService _customerService;

        public AuthController(LoginService loginService, CustomerService customerService)
        {
            // Injicerer en LoginService- og CustomerService-afhængighed for at kunne bruge dem i controllerens metoder.
            _loginService = loginService;
            _customerService = customerService;
        }

        // En offentlig metode, der håndterer login-funktionaliteten.
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginInfo login)
        {
            try
            {
                // Kalder Login-metoden på LoginService-objektet for at forsøge at logge ind med de angivne login-oplysninger.
                return await _loginService.Login(login);
            }
            catch (Exception ex)
            {
                // Logger en fejl, hvis der opstår en exception under login-processen.
                _loginService.Logger.LogError($"Fejl ved login metode: {ex.Message}");
                throw;
            }
        }

        // En offentlig metode, der validerer en JWT-token.
        [AllowAnonymous]
        [HttpPost("validate")]
        public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
        {
            try
            {
                // Kalder ValidateJwtToken-metoden på LoginService-objektet for at validere JWT-tokenen.
                return await _loginService.ValidateJwtToken(token);
            }
            catch (Exception ex)
            {
                // Hvis valideringen fejler, logges en fejlmeddelelse, og der returneres en 404 Not Found statuskode.
                _loginService.Logger.LogError(ex, ex.Message);
                return StatusCode(404);
            }
        }

        // En offentlig metode, der returnerer en liste over metadata om assembly-versionen.
        [HttpGet("version")]
        public IEnumerable<string> Get()
        {
            var properties = new List<string>();
            var assembly = typeof(Program).Assembly; // Henter assembly-metadata for den nuværende applikation.
            foreach (var attribute in assembly.GetCustomAttributesData()) // Gennemgår metadataen for hver attribut i assemblyet.
            {
                properties.Add($"{attribute.AttributeType.Name} - {attribute.ToString()}"); // Tilføjer attributnavnet og dens værdi til listen over metadata.
            }
            return properties; // Returnerer listen over metadata.
        }
    }
}