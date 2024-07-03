using JWT_Authentication.Models;

namespace JWT_Authentication.Services
{
    public interface IUserService
    {
        string Login(User user);


        MyToken RefreshToken(MyToken TokenValue);
    }
}
