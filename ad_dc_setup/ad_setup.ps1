


# Password Generation
add-type -AssemblyName System.Web

$PwLength = 16
$PwSpecialChars = 2

$AdminPassword = [system.web.security.membership]::GeneratePassword($PwLength, $PwSpecialChars) | ConvertTo-SecureString -AsPlainText -Force

$AdRecoveryPassword = [system.web.security.membership]::GeneratePassword($PwLength, $PwSpecialChars) | ConvertTo-SecureString -AsPlainText -Force

# Convert $Password to a strandard string:
# [System.Net.NetworkCredential]::new("", $Password).Password

# Reset administrator password and store it remotely
$AdminPassword | gcloud kms encrypt --plaintext-file - --ciphertext-file AdminPassword.crypt --keyring $GcpKeyRing --location $GcpKeyRingLocation --key $GcpKey

$AdRecoveryPassword | gcloud kms encrypt --plaintext-file - --ciphertext-file AdminPassword.crypt --keyring $GcpKeyRing --location $GcpKeyRingLocation --key $GcpKey


# AD Config
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
Test-ADDSForestInstallation -DomainName test-domain.local -InstallDns -SafeModeAdministratorPassword $Password
Install-ADDSForest -DomainName test-domain.local -InstallDns -SafeModeAdministratorPassword $Password -Force

