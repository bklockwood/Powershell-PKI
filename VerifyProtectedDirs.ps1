<# 
 Simple script to count files that don't have Authenticode sigs in Windows protected areas.
BKL 20150207
I'd like to replace the signtool.exe with native calls to WinVerifyTrust (or its .NET equivalent)
This may come in handy for that: http://poshcode.org/4806
here's a good C example: http://goo.gl/uJnmn9, http://goo.gl/2tKzRq
 Some informative links:
Authenticode signing http://goo.gl/hdjQtB
some files are catalog signed, not Authenticode signed. http://goo.gl/peOVL4, http://goo.gl/uYywCF, 
Code-signing best practices http://goo.gl/O3IbiE
sigcheck http://goo.gl/kj15hK (I did not end up using it)
code-signing caveats, EricLaw http://goo.gl/bGM6Hd
signtool http://goo.gl/RaOWTM,  http://goo.gl/rmSZ6Q
Why Isn't PowerShell.exe Authenticode Signed? http://goo.gl/mu4mmM
#>


<#
.Synopsis
   Walk directory recursively, examining the Authenticode status of all executable files.
.DESCRIPTION
   Walk directory recursively. Optionally show signed/unsigned status of all files. 
   Deliver a summary report.
.EXAMPLE
   Show-SigningStatus -Path c:\Windows\System32 -Showfiles None
   will report:
   Results for c:\windows\system32 :
    Total files:         9044
    Embedded signatures: 5043
    Catalog signatures:  3999
    No signature:        2
#>
function Show-SigningStatus
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    ( 
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [string]$Path,

        # Valid values: All, None, Signed, Unsigned. Default: None
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,Position=1)]
        [string]$ShowFiles 
    )

    Process
    {
        $Embeddedsigcount = 0
        $Catalogsigcount = 0
        $Nosigcount = 0
        $ProcessedCount = 0
        Write-Progress -ID 1 -Activity "Signature status of files on $path"
        Write-Host "Results for $Path :"
        $include = @("*.cab","*.cat","*.ctl","*.dll","*.exe","*.ocx","*.com")
        #now skipping WinSxS folder because a) it's protected and b) I don't understand how signing works there
        $dirwalk = get-childitem -path $Path -File -Include $include -Exclude *winsxs* -Recurse -ErrorAction ignore |
            where {$_.fullname -notlike '*winsxs*'}
        foreach ($item in $dirwalk) {
            $ProcessedCount ++
            if ( $($item.versioninfo.companyname.length) -eq 0) {
                $companyname = "(no company found)"
            } else {
                $companyname = $item.versioninfo.companyname
            }
            $itemprops = "$($item.fullname)  $companyname"
            if ( $(Get-AuthenticodeSignature $($item.fullname)).Status -eq "Valid" ) {
                if ($ShowFiles -eq "Signed" -or $ShowFiles -eq "All") {
                    Write-Host "EMBsigned: $itemprops"
                }
                $Embeddedsigcount ++
                Write-Progress -ID 1 `
                    -Activity "Signature status of $($dirwalk.count) files on $path" `
                    -Status "$ProcessedCount files processed. Embedded: $Embeddedsigcount, Catalog: $Catalogsigcount, No signature: $Nosigcount" `
                    -PercentComplete (( $ProcessedCount / $($dirwalk.count))*100)
            } else {
                $signtool = .\signtool.exe verify /a /pa /ms /sl /q $item.fullname 2>&1
                if ($signtool.exception) {
                    if ($ShowFiles -eq "Unsigned" -or $ShowFiles -eq "All") {
                        Write-Host "NO sig: $itemprops"
                    }
                    $Nosigcount ++
                } else {
                    if ($ShowFiles -eq "Signed" -or $ShowFiles -eq "All") {
                        Write-Host "CATsigned: $itemprops"
                    }
                    $Catalogsigcount ++
                }
            }
        }
        Write-Host "Total files:         $ProcessedCount"
        Write-Host "Embedded signatures: $Embeddedsigcount"
        Write-Host "Catalog signatures:  $Catalogsigcount"
        Write-Host "No signature:        $Nosigcount"
    }

}

# BEGINNING OF SCRIPT

if ( ![Environment]::Is64BitProcess) {
    #If PS is running 32bit, c:\windows\system32 is a redirection of c:\windows\syswow64.
    #signtool can't seem to follow the redirection and gives 'file not found' error which 
    #screws up the script results. So: don't allow this script as a 32bit process.
    #Thanks to Garrett Serack who set me straight on this.
    Write-Warning "You're running from a 32-bit Powershell process. This script needs a 64-bit process."
    break
}

if ( !(Test-Path -path .\signtool.exe) ) {
    Write-Warning "This script requires signtool.exe from the Windows SDK. http://goo.gl/0ylLtC"
    Write-Warning "You need signtool.exe in directory you run this script from. Ending script."
    break
}

Write-Host "In this context, 'executable' means any file with extension *.cab,*.cat,*.ctl,*.dll,*.exe,*.com, or *.ocx"
Write-Host " "

Show-SigningStatus "C:\Program Files" -ShowFiles unsigned
Show-SigningStatus "C:\Program Files (x86)" -ShowFiles unsigned
Show-SigningStatus "C:\Windows" -ShowFiles unsigned
