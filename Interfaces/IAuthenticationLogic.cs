using objects;

namespace question2.Interfaces
{
    public interface IAuthenticationLogic
    {
        Token GenerateBearerToken(APIUser user);
    }
}