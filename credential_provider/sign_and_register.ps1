# PowerShell deployment assistant helper for TAALA-2KEN.
# Provides instructions/execution for code-signing and deploying.

param(
    [string]$Action = "sign",
    [string]$DllPath = ".\build\bin\Release\Taala2KenCredentialProvider.dll"
)

function New-DevelopmentCert {
    Write-Host "[Deploy] Creating self-signed code-signing certificate for testing..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Taala2KenDevRoot" -KeyUsage DigitalSignature -FriendlyName "TAALA-2KEN Development Certificate"
    
    # Export cert
    $certPath = "$env:TEMP\Taala2KenDevRoot.cer"
    Export-Certificate -Cert $cert -FilePath $certPath | Out-Null
    
    # Import to Trusted Root and Trusted Publishers
    Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    
    Write-Host "[Deploy] Certificate initialized and imported into Local Trust Store."
    return $cert
}

function Protect-Dll {
    if (-not (Test-Path $DllPath)) {
        Write-Error "[Deploy] Target DLL not found at $DllPath. Run build.bat first."
        return
    }

    # Find cert or create one
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*Taala2KenDevRoot*" } | Select-Object -First 1
    if ($null -eq $cert) {
        $cert = New-DevelopmentCert
    }

    Write-Host "[Deploy] Signing DLL using signtool..."
    & "signtool.exe" sign /fd SHA256 /sha1 $cert.Thumbprint $DllPath
    Write-Host "[Deploy] Signature embedded successfully."
}

function Register-Dll {
    Write-Host "[Deploy] Registering DLL in Logon system catalog..."
    # Copy DLL to system root
    $systemPath = "$env:windir\System32\Taala2KenCredentialProvider.dll"
    Copy-Item -Path $DllPath -Destination $systemPath -Force
    
    # Register COM Server
    regsvr32.exe /s $systemPath
    Write-Host "[Deploy] COM object registered via regsvr32."
}

switch ($Action) {
    "sign" { Protect-Dll }
    "deploy" { Protect-Dll; Register-Dll }
    "clean" {
        Write-Host "[Deploy] Unregistering and removing DLL..."
        $systemPath = "$env:windir\System32\Taala2KenCredentialProvider.dll"
        if (Test-Path $systemPath) {
            regsvr32.exe /u /s $systemPath
            Remove-Item -Path $systemPath -Force
        }
        Write-Host "[Deploy] Clean up finished."
    }
}
