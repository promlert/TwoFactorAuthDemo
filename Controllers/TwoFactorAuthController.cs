using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using OtpNet;
using QRCoder;

namespace TwoFactorAuthDemo.Controllers
{
    [Authorize] // จำกัดเฉพาะผู้ใช้ที่ล็อกอิน
    public class TwoFactorAuthController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly string _connectionString;

        public TwoFactorAuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        [HttpGet]
        public async Task<IActionResult> EnableTwoFactorAuth()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // สร้าง Secret Key สำหรับ TOTP
            var secretKey = KeyGeneration.GenerateRandomKey(20);
            var base32Secret = Base32Encoding.ToString(secretKey);

            // สร้าง URI สำหรับ QR Code ที่ Microsoft Authenticator อ่านได้
            var email = user.Email;
            var issuer = "TwoFactorAuthDemo";
            var authenticatorUri = $"otpauth://totp/{issuer}:{email}?secret={base32Secret}&issuer={issuer}&digits=6&period=30";

            // สร้าง QR Code สำหรับ Microsoft Authenticator
            using (var qrGenerator = new QRCodeGenerator())
            {
                var qrCodeData = qrGenerator.CreateQrCode(authenticatorUri, QRCodeGenerator.ECCLevel.Q);
                using (Base64QRCode qrCode = new Base64QRCode(qrCodeData))
                {
                    ViewBag.QRCodeImage = $"data:image/png;base64,{qrCode.GetGraphic(20)}";
                }
                //using (var qrCode = new QRCode(qrCodeData))
                //{
                //    using (var qrCodeImage = qrCode.GetGraphic(20))
                //    {
                //        using (var ms = new MemoryStream())
                //        {
                //            qrCodeImage.Save(ms, ImageFormat.Png);
                //            var qrCodeBytes = ms.ToArray();
                //            ViewBag.QRCodeImage = $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";
                //        }
                //    }
                //}
            }

            // บันทึก Secret Key ด้วย Dapper
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.ExecuteAsync(
                    @"MERGE INTO TwoFactorSecrets AS target
                      USING (SELECT @UserId, @SecretKey, @IsTwoFactorEnabled) AS source (UserId, SecretKey, IsTwoFactorEnabled)
                      ON target.UserId = source.UserId
                      WHEN MATCHED THEN
                          UPDATE SET SecretKey = source.SecretKey, IsTwoFactorEnabled = source.IsTwoFactorEnabled
                      WHEN NOT MATCHED THEN
                          INSERT (UserId, SecretKey, IsTwoFactorEnabled)
                          VALUES (source.UserId, source.SecretKey, source.IsTwoFactorEnabled);",
                    new { UserId = user.Id, SecretKey = base32Secret, IsTwoFactorEnabled = true }
                );
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> VerifyTwoFactorCode(string code)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // ดึง Secret Key ด้วย Dapper
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

            // ตรวจสอบรหัส TOTP จาก Microsoft Authenticator
            var totp = new Totp(Base32Encoding.ToBytes(secretKey));
            bool isValid = totp.VerifyTotp(code, out long timeStepMatched, new VerificationWindow(2));

            if (isValid)
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid TOTP code.");
                return View("EnableTwoFactorAuth");
            }
        }
    }
}