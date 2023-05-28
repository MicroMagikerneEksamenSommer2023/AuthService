using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Moq;
using AuthService.Controllers;
using AuthService.Services;
using Microsoft.AspNetCore.Mvc;
using AuthService.Models;

namespace AuthService.Tests;

public class Tests
{
    private ILogger<AuthController> _logger = null;
    private IConfiguration _configuration = null;

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

    private LoginInfo CreateLoginInfo(string email, string accessCode){

        var loginInfo = new LoginInfo(email, accessCode);

        return loginInfo;
    }
}
