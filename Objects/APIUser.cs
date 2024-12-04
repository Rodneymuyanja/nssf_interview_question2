
using System.ComponentModel.DataAnnotations;

namespace objects
{
    public class APIUser
    {
        [MinLength(5, ErrorMessage = "Name can not be this short, gentlemen please :.( .")]
        public string? Username { get; set; }
        public string? Password { get; set; }

    }

}