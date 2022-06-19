using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TokenBasedAuthentication.Entities;
using TokenBasedAuthentication.Helpers;

namespace TokenBasedAuthentication.Services
{
    public interface IUserService
    {
        User Authenticate(string kullaniciAdi, string sifre);
        IEnumerable<User> GetAll();
    }

    public class UserService : IUserService
    {
        // Kullanıcılar veritabanı yerine manuel olarak listede tutulamaktadır. Önerilen tabiki veritabanında hash lenmiş olarak tutmaktır.
        private List<User> _users = new List<User>
        {
            new User { Id = 1, Name = "Burak", Surname = "Coskun", Username = "burakc34", Password = "1234" },
            new User { Id = 1, Name = "Deniz", Surname = "Erdem", Username = "deniz06", Password = "4321" }
        };

        private readonly AppSettings _appSettings;

        public UserService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        public User Authenticate(string userName, string pass)
        {
            var user = _users.SingleOrDefault(x => x.Username == userName && x.Password == pass);

            // Eğer kullanıcı bulunmadıysa null dönmesi için.
            if (user == null)
                return null;

            // Authentication başarılı ise token üretme alanı
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            user.Token = tokenHandler.WriteToken(token);

            // Şifreyi güvenlik için null gönderilir.
            user.Password = null;

            return user;
        }

        public IEnumerable<User> GetAll()
        {
            return _users.Select(x => {
                x.Password = null;
                return x;
            });
        }

    }
}
