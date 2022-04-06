namespace JWTClaimAPI.DTOs
{
    public class UserListDTO
    {
        public UserListDTO(string fullname, string email, string role)
        {
            FullName = fullname;
            Email = email;
            Role = role;
        }

        public string FullName { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
        public string Role { get; set; }
    }
}
