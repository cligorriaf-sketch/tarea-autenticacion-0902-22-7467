$ErrorActionPreference = "Stop"
$iterations = 600000
$salt = [byte[]]::new(16)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
$securePassword = Read-Host "Nueva contraseña de demostración" -AsSecureString
$passwordPointer = [IntPtr]::Zero

try {
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    $derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
        $password,
        $salt,
        $iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        32
    )
    $encodedHash = "$iterations`$$([Convert]::ToBase64String($salt))`$$([Convert]::ToBase64String($derivedKey))"
    $project = Join-Path $PSScriptRoot "..\LocalAuth.Api.csproj"
    & dotnet user-secrets set "Demo:PasswordHash" $encodedHash --project $project
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet user-secrets failed with exit code $LASTEXITCODE"
    }
}
finally {
    if ($passwordPointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $password = $null
    $securePassword.Dispose()
}

Write-Host "Password hash saved to this project's User Secrets."
