using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace CSharpIDP.Controllers
{
  [ApiController]
  [Route("[controller]")]
  public class AuthenticationController : ControllerBase
  {
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(ILogger<AuthenticationController> logger)
    {
      _logger = logger;
    }

    [HttpPost]
    public async Task<IActionResult> Token([FromBody] LoginModel model)
    {
      var tokenString = await AuthenticatePostAsync(model);
      if (tokenString != "")
      {
        //Verify(tokenString);
        return Ok(new { token = tokenString });
      }
      return Unauthorized();
    }
    private bool Verify(string token)
    {
      var pemStr = System.IO.File.ReadAllText(@"./jwtES256.key.pub");
      var ecdsa = ECDsa.Create();
      ecdsa.ImportSubjectPublicKeyInfo(ConvertPublicKeyToDer(pemStr), out _);

      var parameters = new TokenValidationParameters()
      {
        ValidateIssuer = true,
        ValidIssuer = "https://localhost:5001/",
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new ECDsaSecurityKey(ecdsa),
        ValidateAudience = false,
        ValidateLifetime = false,
      };
      var tokenHandler = new JwtSecurityTokenHandler();

      try
      {
        var result = tokenHandler.ValidateToken(token, parameters, out SecurityToken securityToken);
        Console.WriteLine(securityToken);
        Console.WriteLine(result);
        return true;
      }
      catch (Exception ex)
      {
        Console.WriteLine(ex);
        return false;

      }
    }
    private static byte[] ConvertPublicKeyToDer(string pemContents)
    {
      var base64 = pemContents
          .Replace("-----BEGIN PUBLIC KEY-----", string.Empty)
          .Replace("-----END PUBLIC KEY-----", string.Empty)
          .Replace("\r\n", string.Empty)
          .Replace("\n", string.Empty);
      Console.WriteLine(base64);
      var der = Convert.FromBase64String(base64);
      return der;
    }

    private async Task<string> AuthenticatePostAsync([FromBody] LoginModel model)
    {
      _logger.LogInformation("Authenticate");

      var user = await FetchUserAsync(model.Email);

      if (user.Email == model.Email && user.Password == model.Password)
      {
        var tokenString = GenerateToken(user);
        return tokenString;
      }
      return "";
    }
    private string GenerateToken(UserInfo user)
    {
      var claims = new[] {
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Sid, user.UserId.ToString()),
        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
        new Claim(JwtRegisteredClaimNames.Email, user.Email)
      };

      var pemStr = System.IO.File.ReadAllText(@"./jwtES256.key");
      var ecdsa = ECDsa.Create();
      var der = ConvertX509PemToDer(pemStr);
      ecdsa.ImportECPrivateKey(der, out _);
      var key = new ECDsaSecurityKey(ecdsa);
      var creds = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
      //var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("securityKey12345"));
      //var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

      var token = new JwtSecurityToken(
        "https://localhost:5001/",
        "https://localhost:5001/",
        claims: claims,
        expires: DateTime.Now.AddMinutes(600),
        signingCredentials: creds
      );

      return new JwtSecurityTokenHandler().WriteToken(token);
    }
    private static byte[] ConvertX509PemToDer(string pemContents)
    {
      var base64 = pemContents
          .Replace("-----BEGIN EC PRIVATE KEY-----", string.Empty)
          .Replace("-----END EC PRIVATE KEY-----", string.Empty)
          .Replace("\r\n", string.Empty)
          .Replace("\n", string.Empty);
      return Convert.FromBase64String(base64);
    }
    private async Task<UserInfo> FetchUserAsync(string email)
    {
      _logger.LogInformation($"fetch user data by email={email}");
      return await Task.Run(() => new UserInfo
      {
        UserId = 888,
        UserName = "user",
        Email = "aaa@gmail.com",
        Password = "password",
        Groups = new int[] { 1, 2, 3 }
      });
    }
  }
  public interface LoginModel
  {
    public string Email { get; set; }
    public string Password { get; set; }
  }
  public class UserInfo
  {
    public int UserId { get; set; }
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public string? Password { get; set; }
    public int[]? Groups { get; set; }
  }
}
