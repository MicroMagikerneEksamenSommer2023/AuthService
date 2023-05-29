using NUnit.Framework;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Moq;
using AuthService.Controllers;
using AuthService.Services;
using Microsoft.AspNetCore.Mvc;
using AuthService.Models;

namespace AuthService.Tests;

public class ServiceTest
{
    // Attributter til ILogger og IConfuguration
    private ILogger<AuthController> _logger = null;
    private IConfiguration _configuration = null;

    // Opsætter testmiljøet ved at initialisere _logger og _configuration
    [SetUp]
    public void Setup()
    {
          _logger = new Mock<ILogger<AuthController>>().Object;

        var myConfiguration = new Dictionary<string, string?>
        {
            {"AuthServiceBrokerHost", "http://testhost.local"}
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(myConfiguration)
            .Build();
    }

    // Tester login med succes
    [Test]
    public async Task LoginTest_Succes()
    {
        //Arrange
        var loginInfo = CreateLoginInfo("mail@mail.dk", "hej1234");
        var token = "JWT-token";

        var stubService = new Mock<ILoginService>();

        stubService.Setup(svc => svc.Login(loginInfo))
            .Returns(Task.FromResult<IActionResult>(new OkObjectResult("")));

        stubService.Setup(svc => svc.ValidateJwtToken(token))
            .Returns(Task.FromResult<IActionResult>(new OkObjectResult("")));    
        
        var controller = new AuthController(_logger, _configuration, stubService.Object);

        //Act
        var result = await controller.Login(loginInfo);

        //Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>()); 
    }

    // Tester login med failure
    [Test]
    public async Task LoginTest_Failure()
    {
        //Arrange
        var loginInfo = CreateLoginInfo("mail@mail.dk", "hej1234");

        var stubService = new Mock<ILoginService>();

        stubService.Setup(svc => svc.Login(loginInfo))
            .Returns(Task.FromResult<IActionResult>(new UnauthorizedResult())); 
        
        var controller = new AuthController(_logger, _configuration, stubService.Object);

        //Act
        var result = await controller.Login(loginInfo);

        //Assert
        Assert.That(result, Is.TypeOf<UnauthorizedResult>()); 
    }

    // Tester validering af JWT token med succes
    [Test]
    public async Task ValidateJwtTokenTest_Succes()
    {
        //Arrange
        string token = "JWT-token";

        var stubService = new Mock<ILoginService>();

        stubService.Setup(svc => svc.ValidateJwtToken(token))
            .Returns(Task.FromResult<IActionResult>(new OkObjectResult(""))); 
        
        var controller = new AuthController(_logger, _configuration, stubService.Object);

        //Act
        var result = await controller.ValidateJwtToken(token);

        //Assert
        Assert.That(result, Is.TypeOf<OkObjectResult>());
    }

    // Tester validering af JWT token med failure
    [Test]
    public async Task ValidateJwtTokenTest_Failure()
    {
        //Arrange
        string token = "JWT-token";

        var stubService = new Mock<ILoginService>();

        stubService.Setup(svc => svc.ValidateJwtToken(token))
            .ThrowsAsync(new Exception()); 
        
        var controller = new AuthController(_logger, _configuration, stubService.Object);

        //Act
        var result = await controller.ValidateJwtToken(token);

        //Assert
        Assert.That(result, Is.TypeOf<StatusCodeResult>());
    }

    /// <summary>
    /// Helper method for creating LoginInfo instance.
    /// </summary>
    /// <returns></returns>
    private LoginInfo CreateLoginInfo(string email, string accessCode){

        var loginInfo = new LoginInfo(email, accessCode);

        return loginInfo;
    }
}
