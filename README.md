# Powershell
Scripts for checking your certificate store, and code-sgning status of executables.

* **Audit-TrustedRootCA.ps1** Checks Windows certificate stores for possibly untrustworthy certs. [Read more.] (http://www.itcookbook.net/blog/auditingyourrootcertificates)
    * **Sept2014-WindowsRootCAList.txt**  List of thumbprints for use with Audit-TrustedRootCA.ps1
* **VerifyProtectedDirs.ps1** Checks executables in Windows protected dirs for code-signing status. [Read more.] (http://www.itcookbook.net/blog/codesigningisimportantwhydoesntmicrosoftdomoreofit)
