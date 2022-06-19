using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TokenBasedAuthentication.Services;

namespace TokenBasedAuthentication.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;
        public UsersController(IUserService userService)
        {
            _userService = userService;
        }
        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] User userParam)
        {
            var user = _userService.Authenticate(userParam.KullaniciAdi, userParam.Sifre);
            if (user == null)
                return BadRequest(new { message = "Kullanici veya şifre hatalı!" });
            return Ok(user);
        }
        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }
    }
}
