<#
    
    .SYNOPSIS
        Renew Certificate
    
    .DESCRIPTION
        Renew Certificate

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Update-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $username,
        [Parameter(Mandatory = $true)]
        [String]
        $password,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $sameKey,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $isRenew,
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
        [Parameter(Mandatory = $true)]
        [String]
        $RemoteComputer
    )
    
    $pw = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object PSCredential($username, $pw)
    
    Invoke-Command -Computername $RemoteComputer -ScriptBlock {
        param($Path, $isRenew, $sameKey)
        $global:result = ""
    
        $Cert = Get-Item -Path $Path
    
        $Template = $Cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if (!$Template) {
            $global:result = "NoTemplate"
            $global:result
            exit
        }
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379399(v=vs.85).aspx
        #X509CertificateEnrollmentContext
        $ContextUser                      = 0x1
        $ContextMachine                   = 0x2
        $ContextAdministratorForceMachine = 0x3
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        #EncodingType
        $XCN_CRYPT_STRING_BASE64HEADER        = 0
        $XCN_CRYPT_STRING_BASE64              = 0x1
        $XCN_CRYPT_STRING_BINARY              = 0x2
        $XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3
        $XCN_CRYPT_STRING_HEX                 = 0x4
        $XCN_CRYPT_STRING_HEXASCII            = 0x5
        $XCN_CRYPT_STRING_BASE64_ANY          = 0x6
        $XCN_CRYPT_STRING_ANY                 = 0x7
        $XCN_CRYPT_STRING_HEX_ANY             = 0x8
        $XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9
        $XCN_CRYPT_STRING_HEXADDR             = 0xa
        $XCN_CRYPT_STRING_HEXASCIIADDR        = 0xb
        $XCN_CRYPT_STRING_HEXRAW              = 0xc
        $XCN_CRYPT_STRING_NOCRLF              = 0x40000000
        $XCN_CRYPT_STRING_NOCR                = 0x80000000
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379430(v=vs.85).aspx
        #X509RequestInheritOptions
        $InheritDefault                = 0x00000000
        $InheritNewDefaultKey          = 0x00000001
        $InheritNewSimilarKey          = 0x00000002
        $InheritPrivateKey             = 0x00000003
        $InheritPublicKey              = 0x00000004
        $InheritKeyMask                = 0x0000000f
        $InheritNone                   = 0x00000010
        $InheritRenewalCertificateFlag = 0x00000020
        $InheritTemplateFlag           = 0x00000040
        $InheritSubjectFlag            = 0x00000080
        $InheritExtensionsFlag         = 0x00000100
        $InheritSubjectAltNameFlag     = 0x00000200
        $InheritValidityPeriodFlag     = 0x00000400
        $X509RequestInheritOptions = $InheritTemplateFlag
        if ($isRenew) {
            $X509RequestInheritOptions += $InheritRenewalCertificateFlag
        }
        if ($sameKey) {
            $X509RequestInheritOptions += $InheritPrivateKey
        }
    
        $Context = $ContextAdministratorForceMachine
    
        $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $PKCS10.Silent=$true
    
        $PKCS10.InitializeFromCertificate($Context,[System.Convert]::ToBase64String($Cert.RawData), $XCN_CRYPT_STRING_BASE64, $X509RequestInheritOptions)
        $PKCS10.AlternateSignatureAlgorithm=$false
        $PKCS10.SmimeCapabilities=$false
        $PKCS10.SuppressDefaults=$true
        $PKCS10.Encode()
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa377809(v=vs.85).aspx
        $Enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $Enroll.InitializeFromRequest($PKCS10)
        $Enroll.Enroll()
    
        if ($Error.Count -eq 0) {
            $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
            $Cert.Import([System.Convert]::FromBase64String($Enroll.Certificate(1)))
            $global:result = $Cert.Thumbprint
        }
    
        $global:result
    
    } -Credential $credential -ArgumentList $Path, $isRenew, $sameKey
    
}