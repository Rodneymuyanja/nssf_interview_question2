namespace objects
{
    public class Token
    {
        public string? BearerToken { get; set; }
        public long Expires { get; set; }
        public string? ExpiryDescription { get; set; }
    }

    public class ValidateTokenRequest
    {
        public string? Token { get; set; }
    }
}