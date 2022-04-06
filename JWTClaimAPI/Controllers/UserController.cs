using JWTClaimAPI.DTOs;
using JWTClaimAPI.Model;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTClaimAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {


        private readonly ILogger<UserController> _logger;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTConfig _jwtConfig;

        public UserController(ILogger<UserController> logger, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IOptions<JWTConfig> jwtConfig, RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtConfig = jwtConfig.Value;
            _roleManager = roleManager;
        }


        [HttpPost("register")]
        public async Task<object> Register([FromBody] RegisterDTO model)
        {
            try
            {
                
                var user = new AppUser() { FullName = model.FullName, Email = model.Email, UserName = model.Email, DateCreated = DateTime.UtcNow, DateModified = DateTime.UtcNow };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var tempUser =await _userManager.FindByEmailAsync(model.Email);
                    await _userManager.AddToRoleAsync(tempUser, "User");
                    return await Task.FromResult("User qeydiyyatdan kecdi.");
                }
                return await Task.FromResult(string.Join(",", result.Errors.Select(x => x.Description).ToArray()));
            }
            catch (Exception error)
            {
                return await Task.FromResult(error.Message);
            }
        }

        [Authorize()]
        [HttpGet("getallusers")]
        public async Task<object> GetAllUser()
        {
            try
            {
                List<UserListDTO> userLists = new List<UserListDTO>();
                var users = _userManager.Users.ToList();

                foreach (var user in users)
                {
                    var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
                    userLists.Add(new UserListDTO(user.FullName, user.Email,role));
                }

                return await Task.FromResult(userLists);
            }
            catch (Exception error)
            {
                return await Task.FromResult(error.Message);
            }
        }

        [Authorize(Roles = "User")]
        [HttpGet("getuser")]
        public async Task<object> GetUser()
        {
            try
            {
                List<UserListDTO> userLists = new List<UserListDTO>();
                var users = _userManager.Users.ToList();

                foreach (var user in users)
                {
                    var role = (await _userManager.GetRolesAsync(user)).FirstOrDefault();
                    if (role == "User")
                    {
                        userLists.Add(new UserListDTO(user.FullName, user.Email, role));
                    }
                }

                return await Task.FromResult(userLists);
            }
            catch (Exception error)
            {
                return await Task.FromResult(error.Message);
            }
        }


        [HttpPost("login")]
        public async Task<object> Login([FromBody] LoginDTO model)
        {
            try
            {
                if (model.Email == "" || model.Password == "")
                {
                    return await Task.FromResult("Bos xana qoymayin.");
                }

                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false,false);
                if (result.Succeeded)
                {
                    var appUser = await _userManager.FindByEmailAsync(model.Email);
                    var role = (await _userManager.GetRolesAsync(appUser)).FirstOrDefault();
                    var user = new UserListDTO(appUser.FullName,appUser.Email,role);
                    user.Token = GenerateToken(appUser,role);
                    return await Task.FromResult(user);
                }

                return await Task.FromResult("Login ve ya sifre yanlisdir.");
            }
            catch (Exception error)
            {
                return await Task.FromResult(error.Message);
            }
        }


        [Authorize(Roles = "Admin")]
        [HttpPost("addrole")]
        public async Task<object> Role([FromBody] RoleDTO model)
        {
            try
            {
                if (model == null || model.Role == "")
                {
                    return await Task.FromResult("Bos xana qoymayin.");
                }
                if (await _roleManager.RoleExistsAsync(model.Role))
                {
                    return await Task.FromResult("Bele vezife artiq movcuddur.");
                }

                var role = new IdentityRole();
                role.Name = model.Role;
                var result = await _roleManager.CreateAsync(role);
                if (result.Succeeded)
                {
                    return await Task.FromResult("Vezife yaradildi.");
                }
                return await Task.FromResult("Xeta bas verdi.");
            }
            catch (Exception error)
            {

                return await Task.FromResult(error.Message);
            }
        }

        private string GenerateToken(AppUser user, string role)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new System.Security.Claims.Claim(JwtRegisteredClaimNames.NameId, user.Id),
                    new System.Security.Claims.Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new System.Security.Claims.Claim(ClaimTypes.Role,role),
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature),
                Audience = _jwtConfig.Audience,
                Issuer = _jwtConfig.Issuer
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }
    }
}