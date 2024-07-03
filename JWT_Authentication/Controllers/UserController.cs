using JWT_Authentication.Models;
using JWT_Authentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public IActionResult Login(User user)
        {
            var token = _userService.Login(user);
            if (token == null || token == string.Empty)
            {
                return BadRequest(new { message = "UserName or Password is incorrect" });
            }
            return Ok(token);
        }




        // GET: api/Security
        [HttpGet]
        public IActionResult Get(MyToken TokenValue)
        {
            var token = _userService.RefreshToken(TokenValue);
            return Ok(token);

        }
    }
}