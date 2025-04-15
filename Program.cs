using System.Text;
using AuthProvider.Data;
using AuthProvider.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalhost3000", policy =>
    {
        policy.WithOrigins("http://localhost:3000")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
// Add services to the container.
builder.Services.AddControllers();

// Configure EF Core with SQL Server (Azure SQL)
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Configure ASP.NET Identity with ApplicationUser and IdentityRole
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
 // Customize password options if necessary
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure JWT Authentication
var jwtSecret = builder.Configuration["Jwt:Secret"];
var key = Encoding.UTF8.GetBytes(jwtSecret!);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Set true in production
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero
    };
});
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CreateSuperAdminPolicy", policy => policy.RequireRole("SuperAdmin"));
    options.AddPolicy("CreateAdminPolicy", policy => policy.RequireRole("SuperAdmin"));
    options.AddPolicy("CreateTeacherPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("CreateStudentPolicy", policy => policy.RequireRole("Teacher"));
});

// Optionally, add Swagger for API documentation
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

//using (var scope = app.Services.CreateScope())
//{
//    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
//    context.Database.ExecuteSqlRaw("DELETE FROM AspNetUserRoles");
//    context.Database.ExecuteSqlRaw("DELETE FROM AspNetUsers");
//    context.Database.ExecuteSqlRaw("DELETE FROM AspNetRoles");
//    await context.SaveChangesAsync();
//}

//await DbInitializer.InitializeAsync(app.Services);

// Configure the HTTP request pipeline.
app.UseCors("AllowLocalhost3000");

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
