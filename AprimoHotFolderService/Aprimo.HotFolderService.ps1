[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]
    $Path,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Nothing", "DeleteFile", "DeleteBase", IgnoreCase = $true)]
    [string]
    $ActionOnSuccess,

    [Parameter(Mandatory = $false)]
    [ValidatePattern("[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}", Options = "IgnoreCase")]
    #" <-- fixes syntax highlighting in Visual Studio Code (https://github.com/PowerShell/vscode-powershell/issues/315, https://github.com/PowerShell/EditorSyntax/issues/26)
    [string]
    $Classification,

    [Parameter(Mandatory = $false)]
    [string]
    $FailedFilesFolder,

    [Parameter(Mandatory = $false)]
    [Switch]
    $ClassifySubFolders,

    [Parameter(Mandatory = $false)]
    [string]
    $MetaDataFile,

    [Parameter(Mandatory = $false)]
    [string]
    $MetaDataSchemaName
)

begin {
    Import-Module "$PSScriptRoot/modules/Aprimo.HotFolderService.Functions.psm1" -Force

    Start-Log

    Add-Types -Verbose:($PSBoundParameters['Verbose'] -eq $true)
}

process {

    if ($FailedFilesFolder -and (-not (Test-Path $FailedFilesFolder))) {
        Write-DebugLog "Creating $FailedFilesFolder..."
        New-Item -Path $FailedFilesFolder -ItemType Directory | Out-Null
    }

    if($PSBoundParameters['MetaDataFile'] -and (-not(Test-Path($PSBoundParameters['MetaDataFile'])))) {
        Write-InfoLog "The metadata file '$MetaDataFile' does not exist."
        return
    }

    if($PSBoundParameters['MetaDataFile'] -and (-not([IO.Path]::GetExtension($PSBoundParameters['MetaDataFile']) -eq '.csv'))) {
        Write-InfoLog "Invalid metadata file '$MetaDataFile'. We only support CSV files."
        return
    }

    if(($PSBoundParameters.ContainsKey('MetaDataFile') -and -not($PSBoundParameters.ContainsKey('MetaDataSchemaName')))){
        Write-InfoLog "When uploading a metadata file both parameters MetaDataFile and MetaDataSchemaName are required."
        return
    }

    [hashtable]$entries = Get-FileList -Path $Path -FailedFilesFolder $FailedFilesFolder

    if ($entries.get_Count() -eq 0) {
        Write-DebugLog "No files to upload"
        return
    }

    Initialize-Session -Verbose:($PSBoundParameters['Verbose'] -eq $true)


    $metaDataFileUploadTokens = @{}
    if($MetaDataFile){
        if (Test-Path $MetaDataFile) {

            UploadMetadataFile -path $PSBoundParameters['MetaDataFile'] -metadataFileTable $metaDataFileUploadTokens
        }
    }

    $i = 0
    $totalTimeSpent = 0
    $timeLeft = 0
    $totalSuccess = 0
    $totalFailed = 0
    foreach ($entry in $entries.GetEnumerator() | Sort-Object -Property name) {
        $i++

        $filePath = $entry.Key -replace [regex]::escape($Path), ""
        $subFoldersStr = (Split-Path -Path $filePath)

        $subClassifications = @()
        if ($ClassifySubFolders) {
            $subClassifications = $subFoldersStr.Split('\\', [System.StringSplitOptions]::RemoveEmptyEntries)
        }

        if (-not (Test-Path -LiteralPath $entry.Key)) {
            continue
        }

        # continue when file itself is the main metadata file
        if($MetaDataFile -and $entry.Key -eq $MetaDataFile){
            continue
        }

        $isFileLocked = $false
        try {

            $oFile = New-Object System.IO.FileInfo $entry.Key
            $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

            if ($oStream) {
                $oStream.Close()
            }
        } catch {
            # file is locked by a process.
            $isFileLocked = $true
        }

        if ($isFileLocked -eq $true) {
            continue
        }

        $secondsRemaining = ($timeLeft / 1000)
        if ($secondsRemaining -eq 0) {
            $secondsRemaining = -1
        }

        Write-Progress -Id 1 -Activity "Uploading files" -Status "Uploading $i of $($entries.get_Count()) files" -PercentComplete ((($i - 1) / $entries.get_Count()) * 100) -SecondsRemaining $secondsRemaining

        [System.Diagnostics.Stopwatch]$sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {

            $metadataTokenToUse = ""
            $metadataFileToUse = ""

            # When metadata file is passed as param this is always leading
            if($MetaDataFile){
                $metadataFileToUse = $MetaDataFile
                $metadataTokenToUse = $metaDataFileUploadTokens.Item($MetaDataFile)
            }

            if($entry.Value){
                # Do not use the attached metadata file when a global metadata file is used.
                if($MetaDataFile){
                    Write-WarningLog "Skip metadata file '$($entry.Key)'. Another metadata file is passed to the commandline"

                    # can be (re)moved already by a previous file
                    if(Test-Path($entry.Value)){

                        AddToFailedFolder -Path $entry.Value -FailedFilesFolder $FailedFilesFolder -SubFolders $subFoldersStr
                    }
                }
                # Only when schema name is present
                elseif($MetaDataSchemaName){
                    # when metadata file not already uploaded upload the file
                    # same metadata file can be re-used for other files
                    if(-not $metaDataFileUploadTokens.ContainsKey($entry.Value)){
                        UploadMetadataFile -path $entry.Value -metadataFileTable $metaDataFileUploadTokens
                    }

                    $metadataFileToUse = $entry.Value
                    $metadataTokenToUse = $metaDataFileUploadTokens.Item($entry.Value)
                }

            }
            $message = "Start upload file: $filePath."
            if($metadataFileToUse -and $MetaDataSchemaName){
                $message += " Metadata file: $metadataFileToUse. Schema name: $MetaDataSchemaName"
            }
            else{
                $message += " Metadata file: None"
            }
            Write-InfoLog $message

            New-Record -Path $entry.Key -Classification $Classification -SubClassifications $subClassifications -Verbose:($PSBoundParameters['Verbose'] -eq $true) -MetaDataFileToken $metadataTokenToUse -MetaDataSchemaName $MetaDataSchemaName | Out-Null
            Remove-ProcessedFile -Path $entry.Key -ActionOnSuccess $ActionOnSuccess -Verbose:($PSBoundParameters['Verbose'] -eq $true)
            $totalSuccess++
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-ErrorLog "An error occurred while creating a new record for $($entry.Key)`n`n $errorMsg"

            AddToFailedFolder -Path $entry.Key -FailedFilesFolder $FailedFilesFolder -SubFolders $subFoldersStr

            $totalFailed++
        }

        $sw.Stop()
        $elapsed = $sw.ElapsedMilliseconds

        Write-InfoLog "Upload took $($elapsed)ms"
        Write-DebugLog "Upload took $($elapsed)ms"

        $totalTimeSpent += $elapsed
        $timeLeft = ($entries.Length - $i) * ($totalTimeSpent / $i)
    }

    # remove all the uploaded metadata files
    if( $metaDataFileUploadTokens.get_Count() -gt 0){
        Write-InfoLog ("Cleaning uploaded metadata files")
        foreach ($uploadedFile in $metaDataFileUploadTokens.GetEnumerator()){

            $token = [string]$uploadedFile.Value
            $response = DeleteUploadedFile -uri (CreateUrl -endpoint "/$token" -Kind "Upload")
        }
    }


    Write-InfoLog "Total created records $totalSuccess"
    Write-InfoLog "Total failed uploads $totalFailed"
}

end {
    Stop-Log
}