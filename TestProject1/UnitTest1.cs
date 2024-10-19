using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using SampleApp.E2E.Tests;

namespace TestProject1
{
    [TestClass]
    public class UnitTest1 : EndToEndTestCase
    {
        [TestMethod]
        public async Task Should_Reject_Unauthenticated_Requests()
        {
            var response = await Client.GetAsync("/");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.Unauthorized);
        }

        [TestMethod]
        public async Task Should_Allow_Operators_To_Retrieve_Secrets()
        {
            var token = JwtTokenProvider.JwtSecurityTokenHandler.WriteToken(
            new JwtSecurityToken(
            JwtTokenProvider.Issuer,
            JwtTokenProvider.Issuer,
            new List<Claim> { new(ClaimTypes.Role, "Operator"), new("department", "Security") },
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: JwtTokenProvider.SigningCredentials
            )
        );
            
            Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await Client.GetAsync("/secrets");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        [TestMethod]
        public async Task Should_Allow_All_RegisteredUsers()
        {
            var token = new TestJwtToken().WithRole("User").WithUserName("testuser").Build();
            Client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await Client.GetAsync("/");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.OK);
        }

        [TestMethod]
        [DataRow("Admin")]
        [DataRow("Operator")]
        public async Task Should_Allow_Security_Power_Users(string roleName)
        {
            var response = await Client
                .WithJwtBearerToken(token => token.WithRole(roleName).WithDepartment("Security"))
                .GetAsync("/secrets");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.OK);
            Assert.AreEqual(response.Content.ReadAsStringAsync().Result, 42.ToString());
        }

        [TestMethod]
        [DataRow("Admin", "HR")]
        [DataRow("Operator", "Finance")]
        public async Task Should_Reject_Power_Users_From_Other_Departments(
            string roleName,
            string department
        )
        {
            var response = await Client
                .WithJwtBearerToken(token => token.WithRole(roleName).WithDepartment(department))
                .GetAsync("/secrets");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.Forbidden);
        }

        [TestMethod]
        public async Task Should_Reject_Non_Security_PowerUsers()
        {
            var response = await Client
                .WithJwtBearerToken(token => token.WithRole("User").WithDepartment("Security"))
                .GetAsync("/secrets");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.Forbidden);
        }

        [TestMethod]
        public async Task Should_Allow_Global_Admin()
        {
            var response = await Client
                .WithJwtBearerToken(token => token.WithRole("GlobalAdmin").WithDepartment("IT"))
                .GetAsync("/secrets");
            Assert.AreEqual(response.StatusCode, HttpStatusCode.OK);
            Assert.AreEqual(response.Content.ReadAsStringAsync().Result, 42.ToString());
        }
    }
}