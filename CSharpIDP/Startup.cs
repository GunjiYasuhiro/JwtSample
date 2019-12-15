using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IdentityModel.Tokens.Jwt;

namespace CSharpIDP
{
  public class Startup
  {
    public Startup(IConfiguration configuration)
    {
      Configuration = configuration;
    }

    public IConfiguration Configuration { get; }
    private static byte[] ConvertPubKeyToDer(string pemContents)
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
    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
      var pemStr = File.ReadAllText(@"./jwtES256.key.pub");
      var ecdsa = ECDsa.Create();
      var der = ConvertPubKeyToDer(pemStr);
      ecdsa.ImportSubjectPublicKeyInfo(der, out _);

      services.AddControllers();
      services.AddAuthentication(options =>
      {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
      })
        .AddJwtBearer(options =>
      {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
          ValidateIssuer = true,
          ValidIssuer = "https://localhost:5001/",
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = new ECDsaSecurityKey(ecdsa),
          ValidateAudience = false,
          ValidateLifetime = false,
        };
      });
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
      }

      app.UseHttpsRedirection();

      app.UseRouting();

      app.UseAuthentication();
      //app.UseAuthorization();

      app.UseEndpoints(endpoints =>
      {
        endpoints.MapControllers();
      });
    }
  }
}
