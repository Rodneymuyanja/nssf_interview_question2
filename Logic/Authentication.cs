
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using objects;
using question2.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace Logic
{
    public class AuthenticationLogic(IConfiguration _configuration) : IAuthenticationLogic
    //: IAuthentication
    {
        private readonly IConfiguration configuration = _configuration;


        private const string SUBJECT = "sub";
        private const string ISSUED_AT_TIME = "iat";
        private const string MINUTES = "minutes";
        private const string DAYS = "days";
        private const string HOURS = "hours";

        public Token GenerateBearerToken(APIUser user)
        {
            JwtSecurityToken jwtSecurityToken = CreateJWTSecurityToken(user);
            Token token = CreateAuthorizationBearerToken(jwtSecurityToken);

            return token;
        }



        private JwtSecurityToken CreateJWTSecurityToken(APIUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            IEnumerable<System.Security.Claims.Claim> claims = AddClaimsToToken(user);

            var token = new JwtSecurityToken(
                  configuration["Jwt:Issuer"],
                  user.Username,
                  claims,
                  expires: GetExpiryDate(),
                  signingCredentials: credentials
              );


            return token;
        }

        private IEnumerable<System.Security.Claims.Claim> AddClaimsToToken(APIUser user)
        {
            var claims = new[]
           {
                new System.Security.Claims.Claim (JwtRegisteredClaimNames.Sub,user.Username!),
                new System.Security.Claims.Claim (JwtRegisteredClaimNames.Iat,DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            };

            return claims;
        }
        private Token CreateAuthorizationBearerToken(JwtSecurityToken jwtSecurityToken)
        {
            string token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            var exp = long.Parse(configuration["Jwt:Expiry"]!.ToString());

            var AuthorizationBearerToken = new Token()
            {
                BearerToken = token,
                Expires = exp,
                ExpiryDescription = configuration["Jwt:ExpiryDescription"],
            };

            return AuthorizationBearerToken;
        }











        private DateTime GetExpiryDate()
        {
            DateTime expiry = DateTime.Now;
            string expiryDescription = configuration["Jwt:ExpiryDescription"]!.ToString();
            var exp = long.Parse(configuration["Jwt:Expiry"]!.ToString());

            switch (expiryDescription)
            {
                case MINUTES:
                    expiry = DateTime.Now.AddMinutes(exp);
                    break;
                case HOURS:
                    expiry = DateTime.Now.AddHours(exp);
                    break;
                case DAYS:
                    expiry = DateTime.Now.AddDays(exp);
                    break;
                default:
                    break;
            }

            return expiry;
        }


    }


    public class Auth2Validation
    {
        private const string SUBJECT = "sub";
        private const string ISSUED_AT_TIME = "iat";
        private const string MINUTES = "minutes";
        private const string DAYS = "days";
        private const string HOURS = "hours";
        public bool ValidateToken(string BearerToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(BearerToken);

            bool validDetails = ValidateTokenDetails(token, tokenHandler, BearerToken, out string reason);

            if (!validDetails)
            {
                return false;
            }

            bool validBearerToken = ValidateBearerToken(BearerToken, tokenHandler, token);


            return false;
        }

        private static DateTime ConvertFromUnixTime(long unixtimeStamp)
        {
            DateTime datetime = new(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            datetime = datetime.AddSeconds(unixtimeStamp).ToLocalTime();
            return datetime;
        }
        private bool ValidateTokenDetails(JwtSecurityToken? token, JwtSecurityTokenHandler tokenHandler, string BearerToken, out string reason)
        {
            if (!ValidateSubjectAndIat(token, tokenHandler, BearerToken))
            {
                reason = $"Missing subject and Issued at Times";
                return false;
            }

            if (!ValidateTokenAudience(token!))
            {
                reason = $"Invalid token owner";
                return false;
            }

            if (ValidateLifeTime(token!, out long tokenExpiredBy))
            {
                reason = "Invalid lifetime";
                  return false;
            }

            reason = string.Empty;
            return true;
        }
        private bool ValidateSubjectAndIat(JwtSecurityToken? token, JwtSecurityTokenHandler tokenHandler, string BearerToken)
        {
            var sub = token!.Claims.First(claim => claim.Type == SUBJECT).Value;
            var iat = token.Claims.First(claim => claim.Type == ISSUED_AT_TIME).Value;


            if ((sub is null) || (iat is null))
            {

                return false;
            }

            return true;
        }
        private TokenValidationParameters GetValidationParameters()
        {

            string signing_key = "ThisismySecretKeyfromtodayonwordsnowthatyouguyshavestartedcodingeverythingshouldbethenthoughimcurious";
            return new TokenValidationParameters()
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signing_key)),
                ValidAudiences = new[] { "front_end" },
                ValidateAudience = false,
                ValidIssuer = "back_end",
                ValidateIssuer = false,
            };
        }
        private bool ValidateBearerToken(string BearerToken, JwtSecurityTokenHandler tokenHandler, JwtSecurityToken? token)
        {
            try
            {
                var validationParameters = GetValidationParameters();
                IPrincipal principal = tokenHandler.ValidateToken(BearerToken, validationParameters, out SecurityToken validatedToken);
                return principal.Identity!.IsAuthenticated;
            }
            catch (Exception e)
            {

                return false;
            }

        }
        /// <summary>
        /// if we get the time at which we issued this token
        /// and the time now 
        /// 
        /// get the difference (d), depending on the application's settings
        /// either in minutes, hours or days
        /// 
        /// then subtract the token's expiration time from that difference (d)
        /// if the value is a positive it means this token is past it's lifetime
        /// 
        /// if it's negative then it's still active.
        /// 
        /// 
        /// 
        /// the boundary case here is 0
        /// </summary>
        /// <param name="IssuedAtDate"></param>
        /// <returns></returns>
        private bool ValidateLifeTime(JwtSecurityToken token, out long tokenExpiredBy)
        {
            var issuedAtTime = token.Claims.First(claim => claim.Type == ISSUED_AT_TIME).Value;

            DateTime iat = ConvertFromUnixTime(long.Parse(issuedAtTime));

            DateTime now = DateTime.Now;
            var applicationDefinedExpiryTime = 30;
            var differenceBetweenNowAndIat = DifferenceInIssuedAtTimeAndNow(iat, now);
            var differenceSinceTokenDispatch = differenceBetweenNowAndIat - applicationDefinedExpiryTime;

            tokenExpiredBy = differenceSinceTokenDispatch;

            if (differenceSinceTokenDispatch >= 0)
            {
                return true;
            }
            else
            {
                return false;
            }

        }


        public bool ValidateTokenAudience(JwtSecurityToken token)
        {
            var audienceAccordingToToken = token!.Claims.First(claim => claim.Type == SUBJECT).Value;
            if (audienceAccordingToToken == "frontend")
            {
                return true;
            }

            return false;
        }


        private long DifferenceInIssuedAtTimeAndNow(DateTime iat, DateTime now)
        {
            var diff = 0;
            string expiryDescription = MINUTES;

            switch (expiryDescription)
            {
                case MINUTES:
                    diff = (now - iat).Minutes;
                    break;
                case HOURS:
                    diff = (now - iat).Hours;
                    break;
                case DAYS:
                    diff = (now - iat).Days;
                    break;
                default:
                    break;
            }

            return diff;
        }

    }
}