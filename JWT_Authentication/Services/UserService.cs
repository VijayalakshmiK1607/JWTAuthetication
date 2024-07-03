using JWT_Authentication.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT_Authentication.Services
{
    public class UserService : IUserService
    {
        private List<User> _users = new List<User>
        {
          new User{ UserName = "", Password = "" }
        };

        private readonly IConfiguration _configuration;
        public UserService(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        public string Login(User user)
        {           
            var LoginUser = _users.SingleOrDefault(x => x.UserName == user.UserName && x.Password == user.Password);

            if (LoginUser == null)
            {
                return string.Empty;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            //var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(""));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                Expires = DateTime.UtcNow.AddMinutes(30),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            string userToken = tokenHandler.WriteToken(token);
            return userToken;           
        }

        private string GenerateJSONWebToken(string username, int expiryTime)
        {
            // header info
            var algo = SecurityAlgorithms.HmacSha256;

            // payload info
            var claims = new[] {
                new Claim(ClaimTypes.Name, username),
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Email, ""),
                new Claim("IsAdmin", "True"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
            // signature
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(""));
            var credentials = new SigningCredentials(securityKey, algo);
            var token = new JwtSecurityToken("",
               "BrowserClients",
              claims,
              expires: DateTime.Now.AddSeconds(expiryTime),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public MyToken RefreshToken(MyToken tokenApiModel)
        {
            if (tokenApiModel is null)
                throw new Exception("Invalid client request");
            string accessToken = tokenApiModel.TokenValue;
            string refreshToken = tokenApiModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            var username = principal.Identity.Name; //this is mapped to the Name claim by default

            var user = _users.SingleOrDefault(x => x.UserName == username);

            if (user is null || user.RefreshToken != refreshToken)
                throw new Exception("Invalid client request");

            var newAccessToken = GenerateJSONWebToken(user.UserName, 60);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            tokenApiModel.RefreshToken = newRefreshToken;
            tokenApiModel.TokenValue = newAccessToken;
            return tokenApiModel;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "",
                ValidAudience = "BrowserClients",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(""))
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token,
                                        tokenValidationParameters,
                                        out securityToken);
            var user = _users.Find(x => x.UserName == principal.Identity.Name);

            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null
                || user.RefreshTokenExpiryTime <= DateTime.Now)
                throw new SecurityTokenException("Invalid token");
            return principal;
        }
    }
}
