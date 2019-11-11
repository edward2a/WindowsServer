
###
# Pre-Execution check
###
$InitItem = "HKLM:\SYSTEM\CustomerSetup"
$InitProp  = "InitializationSuccessful"
$Init = Get-ItemProperty -Path ${InitItem} -Name ${InitProp}

if (${Iinit}.${InitProp} == 1) {
    Write-Output "Initialization key found, not executing configuration."
    exit 0
}


###
# Imports
###
add-type -AssemblyName System.Web
add-type -AssemblyName System.Net


##
# Vars
###
$PwLength = 16
$PwSpecialChars = 2

$MetadataAttrs = 'http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes'
$MetadataHeaders = @{'Flavor' = 'Google'}
$TransitivePasswordStore = Invoke-RestMethod -Headers ${MetadataHeaders} "${MetadataAttrs}/TransitivePasswordStore"
$KmsEncryptionKey = Invoke-RestMethod -Headers ${MetadataHeaders} "${MetadataAttrs}/KmsEncryptionKey"
$GcpKeyRingLocation, $GcpKeyRing, $GcpKey = ${KmsEncryptionKey}.Split("/", 3)


###
# Generate and set password
###
$AdminPassword = [system.web.security.membership]::GeneratePassword(${PwLength}, ${PwSpecialChars}) | ConvertTo-SecureString -AsPlainText -Force

Get-LocalUser "administrator" | Set-LocalUser -Password ${AdminPassword}


###
# Save encrypted password in target store
###
if (${TransitivePasswordStore}.StartsWith("gs://") {

    [System.Net.NetworkCredential]::new("", ${AdminPassword}).Password | gcloud kms encrypt --plaintext-file - --ciphertext-file AdminPassword.crypt --keyring ${GcpKeyRing} --location ${GcpKeyRingLocation} --key ${GcpKey}

    gsutil cp AdminPassword.crypt ${TransitivePasswordStore}

} elseif (${TransitivePasswordStore}.StartsWith("vault://") {

    Write-Output "Do some forbidden magic to store stuff in vault"

}


###
# Enable Administrator
###
Enable-LocalUser -Name administrator


###
# Set Initialization Status
###
New-ItemPath -Path ${InitItem}
New-ItemProperty -Path ${RegistryPath} -Name ${InitProp} -Value 1 -PropertyType Binary
