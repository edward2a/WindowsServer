###
# Imports
###
add-type -AssemblyName System.Web
add-type -AssemblyName System.Net



###
# Static Vars
###
$LogName = 'Customer Setup'
$LogSources = @(
    'GceMetaStartup',
    'GceMetaShutdown',
    'GceMetaSysprep',
    'InfraManagement'
)
$PwLength = 16
$PwSpecialChars = 2
$MetadataAttrs = 'http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes'
$MetadataHeaders = @{'Flavor' = 'Google'}


###
# Functions
###

# Check log store exists else create it
function Create-CustomerLog {
    param(
        [String]${LogName},
        [String[]]${LogSources})

    try {
        # NOTE: if the event log is empty, the Get-EventLog command will return
        #     an error via stderr that looks like an exception, but it is not,
        #     so silencing it with a redirect to null. #facepalm
        Get-EventLog -LogName ${LogName} -Newest 1 *>$null}

    catch [System.InvalidOperationException] {
        New-EventLog -LogName ${LogName} -Source ${LogSources}}
}


function Write-Event {
    param(
        [String]$type,
        [String]$msg
    )

    $EventMap = @{
        Info = @{ t ='Information'; id = 1000}
        Warn = @{t = 'Warning'; id = 2000}
        Err = @{t = 'Error'; id = 3000}
    }

    # LogName and Source are hard coded because this function
    # is specific to this script.
    Write-EventLog -LogName 'Customer Setup'`
        -Source 'GceMetaStartup'`
        -EntryType ${EventMap}.${type}.t`
        -EventId ${EventMap}.${type}.id`
        -Message ${msg}

    Write-Output "${type}: ${msg}"
}


###
# Pre-Execution check
###
$InitItem = "HKLM:\SYSTEM\CustomerSetup"
$InitProp = "InitializationSuccessful"

$Init = Get-ItemProperty -Path ${InitItem} -Name ${InitProp} 2>$null

if (${Init} -ne $null -And ${Init}.${InitProp} -eq 1) {
    Write-Event Info "Initialization key found, not executing configuration."
    exit 0
} else {
    # Initialize a custom event logger in case it does not exists
    Create-CustomerLog ${LogName} ${LogSources}

    New-Item -Path ${InitItem} | Out-Null
    Write-Event Info "Initialization key ${InitItem}/${InitProp} not found."
}



###
# Runtime Vars
###
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
if (${TransitivePasswordStore}.StartsWith("gs://")) {

    [System.Net.NetworkCredential]::new("", ${AdminPassword}).Password | gcloud kms encrypt --plaintext-file - --ciphertext-file AdminPassword.crypt --keyring ${GcpKeyRing} --location ${GcpKeyRingLocation} --key ${GcpKey}

    gsutil cp AdminPassword.crypt ${TransitivePasswordStore}
    Remove-Item AdminPassword.crypt

} elseif (${TransitivePasswordStore}.StartsWith("vault://")) {

    Write-Output "Do some forbidden magic to store stuff in vault"

}


###
# Enable Administrator
###
Enable-LocalUser -Name administrator


###
# Set Initialization Status
###
New-ItemProperty -Path ${InitItem} -Name ${InitProp} -Value 1 -PropertyType Binary | Out-Null

