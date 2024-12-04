using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Asp.Versioning;
using objects;
using question2.Interfaces;

namespace AuthModule.Controllers.v1
{
    [Route("question2/v{version:apiversion}/auth")]
    [ApiController]
    [ApiVersion("1.0")]
    public class AuthController(IAuthenticationLogic _authentication) : Controller
    {
        private readonly IAuthenticationLogic authentication = _authentication;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="apiUser"></param>
        /// <returns></returns>
        [Route("createtoken")]
        [AllowAnonymous]
        [HttpPost]
        public ActionResult<Token> Authenticate([FromBody] APIUser apiUser)
        {
            return Ok(authentication.GenerateBearerToken(apiUser));
        }
    }
}