

#Requires -Version 2.0 

<#
.Synopsis 
 Compare the list of root certification authorities (CAs) trusted by a user 
 on a computer against a reference list of CAs.  The reference list is just a 
 simple text file of the SHA1 hash thumbprints of root CA certificates. 

.Description
 Compare the list of root certification authorities (CAs) trusted by a user 
 on a computer against a reference list CAs.  The reference list is just a 
 simple text file of the SHA1 hash thumbprints of the CA certificates.  The
 output is a CSV text file of the currently-trusted certificates which are
 NOT in the reference list.  Script also writes an event to the Application
 event log (Event ID = 9017, Source = RootCertificateAudit) on the computer
 where the script is run.  The script is quite simple, actually, and is
 mainly intended as a starter script or skeleton script to be modified for
 the needs of the organization; feel free to add more error handling, etc.

.Parameter FilePath 
 The local or UNC path to the text file containing the list of certificate
 SHA1 hash thumbprints against which to compare as a reference.

.Parameter OutputPath
 The local or UNC path to the folder for the output CSV file which will contain 
 a list of the currently-trusted root CAs which are NOT on the reference
 list of hashes, hence, possibly bad or in violation of policy.

 .Notes
 Refactoring Author: Bryan Lockwood, http://itcookbook.net
 Original Author: Jason Fossen, Enclave Consulting (http://www.sans.org/windows-security/)   
 Version: 2.0
 Updated: 20150224

 Original script and some explaining text are available at http://goo.gl/E3B4tv

 LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
  ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
  A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
  THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
  ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
  LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOT PROHIBITED TO HAVE IT.
 
#>
function Audit-Roots
{
    [CmdletBinding()]
    #[OutputType([int])]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        $FilePath,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=1)]
        $OutputPath
    )

    Process
    {
        # Extract hashes of "Trusted Root Certification Authorities" for the current user.
        $usertrusted  = dir cert:\currentuser\root | foreach { $_ | select-object Thumbprint,Subject}
        # Extract hashes of "Third-Party Trusted Root Certification Authorities" for the current user.
        $usertrusted += dir cert:\currentuser\authroot | foreach { $_ | select-object Thumbprint,Subject}
        # Extract hashes of "Trusted Root Certification Authorities" for the computer.
        $computertrusted = dir cert:\localmachine\root | foreach { $_ | select-object Thumbprint,Subject} 
        # Extract hashes of "Third-Party Trusted Root Certification Authorities" for the computer.
        $computertrusted += dir cert:\localmachine\authroot | foreach { $_ | select-object Thumbprint,Subject} 

        # Combine all the user and computer CA hashes and exclude the duplicates.
        $combined = ($usertrusted + $computertrusted) | sort Thumbprint -unique
        # Read in the hashes from the reference list of thumbprints.
        $reference = get-content -path $FilePath
        # Get list of locally-trusted hashes which are NOT in the reference file.
        $additions = $combined | foreach { if ($reference -notcontains $_.Thumbprint) { $_ } } 

        # Save the list to a CSV file to the output path
        [string]$savepath = "$OutputPath" + "\" + $env:computername
        $savepath = $savepath + "+" + $env:username + "+" + $(get-date -format yyyyMMdd-HHmm) + ".csv"
        $additions | export-csv -notypeinfo -literalpath $savepath

        # Write the list to the local Application event log for archival:
        New-EventLog -LogName Application -Source RootCertificateAudit -ErrorAction SilentlyContinue

        $GoodMessage = "All of the root CA certificates trusted by $env:userdomain\$env:username "
        $GoodMessage = $GoodMessage + "are on the reference list of certificate hashes obtained from "
        $GoodMessage = $GoodMessage + $FilePath

        $BadMessage = "The following root CA certificates are trusted by $env:userdomain\$env:username, "
        $BadMessage = $BadMessage + "`n" + "but they NOT on the supplied hash list ($FilePath): "
        $BadMessage = $BadMessage + "`n" + $($additions | format-list | out-string)

        if ($additions.count -eq 0) { 
            Write-EventLog -logname Application -source RootCertificateAudit -eventID 9017 -message $GoodMessage -EntryType Information 
            Write-Host $GoodMessage  
        } else { 
            Write-EventLog -logname Application -source RootCertificateAudit -eventID 9017 -message $BadMessage -EntryType Warning 
            Write-Warning $BadMessage
        } 

    }
}

Audit-Roots -FilePath .\Feb2015-WindowsRootCAList.txt -OutputPath .\





