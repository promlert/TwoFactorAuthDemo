using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using OtpNet;

namespace TwoFactorAuthDemo.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly string _connectionString;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = new IdentityUser
            {
                Id = Guid.NewGuid().ToString(),
                UserName = email,
                NormalizedUserName = email.ToUpper(),
                Email = email,
                NormalizedEmail = email.ToUpper()
            };

            var result = await _userManager.CreateAsync(user, password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("EnableTwoFactorAuth", "TwoFactorAuth");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return View();
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await _userManager.FindByNameAsync(email.ToUpper());
            if (user != null)
            {
                var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    bool isTwoFactorEnabled;
                    using (var connection = new SqlConnection(_connectionString))
                    {
                        isTwoFactorEnabled = await connection.QuerySingleOrDefaultAsync<bool>(
                            "SELECT IsTwoFactorEnabled FROM TwoFactorSecrets WHERE UserId = @UserId",
                            new { UserId = user.Id });
                    }

                    if (isTwoFactorEnabled)
                    {
                        HttpContext.Session.SetString("UserId", user.Id);
                        return RedirectToAction("VerifyTwoFactorCode", "Account");
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return RedirectToAction("Index", "Home");
                    }
                }
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View();
        }

        [HttpGet]
        public IActionResult VerifyTwoFactorCode()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> VerifyTwoFactorCode(string code)
        {
            var userId = HttpContext.Session.GetString("UserId");
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            string secretKey;
            using (var connection = new SqlConnection(_connectionString))
            {
                secretKey = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT SecretKey FROM TwoFactorSecrets WHERE UserId = @UserId",
                    new { UserId = user.Id }
                );
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                return BadRequest("2FA not configured.");
            }

            var totp = new Totp(Base32Encoding.ToBytes(secretKey));
            bool isValid = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(2));

            if (isValid)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                HttpContext.Session.Remove("UserId");
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid TOTP code.");
                return View();
            }
        }
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public async Task<IActionResult> ResendCode()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            string secretKey;
            using (var connection = new SqlConnection(_connectionString))
            {
                secretKey = await connection.QuerySingleOrDefaultAsync<string>(
                    "SELECT SecretKey FROM TwoFactorSecrets WHERE UserId = @UserId",
                    new { UserId = user.Id });
            }

            if (string.IsNullOrEmpty(secretKey))
            {
                return BadRequest("2FA not configured.");
            }

            var totp = new Totp(Base32Encoding.ToBytes(secretKey));
            var newCode = totp.ComputeTotp(); // สร้างรหัส TOTP ใหม่
            ViewBag.ResendCode = newCode; // ส่งรหัสใหม่ไปแสดงใน View

            return View("VerifyTwoFactorCode"); // กลับไปหน้าเดิมพร้อมรหัสใหม่
        }
    }
}