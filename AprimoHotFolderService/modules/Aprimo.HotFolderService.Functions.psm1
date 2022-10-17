$ErrorActionPreference = "Stop"

$script:appSettings = $null
$script:version = "1.0.20720.10724"
$script:userAgent = $null
$script:token = @{ accessToken = ""; refreshToken = "" }

[long] $threshold = 20 * 1024 * 1024

#region Support methods 

function GetHumanReadableFileSize ([long] $fileSize) {
    $stringBuilder = New-Object System.Text.StringBuilder 1024

    [Aprimo.HotfolderService.Win32]::FormatByteSize($fileSize, $stringBuilder) | Out-Null
    return $stringBuilder.ToString()
}

function GetProxyUri([string]$uri) {
    [System.Net.IWebProxy]$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    if (-not $proxy) {
        Write-DebugLog "No proxy found"
        return $null
    }
    
    if ($proxy.IsBypassed($uri)) {
        Write-DebugLog "Proxy is bypassed for $uri"
        return $null
    }

    $proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    return $proxy.GetProxy($uri)
}

function InvokeRestMethod([string]$uri, [ValidateSet("POST", "GET", "DELETE", "PUT", IgnoreCase = $true)][string]$method = "GET", [Hashtable]$headers = $null, [string]$body = $null, [bool]$refreshToken = $true) {
    $arguments = @{
        Uri    = $uri
        Method = $method
        UseBasicParsing = $true
    }

    if ($headers) {
        $mapping = @{
            "Content-Type"     = "ContentType"
            "User-Agent"       = "UserAgent"
            "Content-Encoding" = "TransferEncoding"
        }

        [Hashtable]$mutableHeaders = $headers.Clone()

        foreach ($header in $mapping.Keys) {
            if (-not $mutableHeaders.ContainsKey($header)) {
                continue
            }

            $arguments.Add($mapping[$header], $mutableHeaders[$header])
            $mutableHeaders.Remove($header)
        }

        $sb = New-Object System.Text.StringBuilder
        [void] $sb.Append("Headers:")

        foreach ($header in $mutableHeaders.keys) {
            [void] $sb.AppendLine()
            [void] $sb.Append("  $header = $($mutableHeaders[$header])")
        }

        Write-DebugLog ($sb.ToString())

        $arguments.Add("Headers", $mutableHeaders)
    }

    if ($body) {
        $truncatedBody = $body.Substring(0, [System.Math]::Min(100, $body.Length))
        if ($truncatedBody.Length -lt $body.Length) {
            $truncatedBody = "$truncatedBody <truncated>"
        }

        Write-DebugLog "Body: $truncatedBody"

        $arguments.Add("Body", $body)
    }

    $proxyUri = GetProxyUri $uri
    if ($proxyUri) {
        Write-DebugLog "Using proxy $proxyUri"
        $arguments.Add("Proxy", $proxyUri)
        $arguments.Add("ProxyUseDefaultCredentials", $true)
    }

    do {
        $currentProgressPreference = $ProgressPreference

        try {

            $ProgressPreference = "SilentlyContinue"            
            return Invoke-WebRequest @arguments | ConvertFrom-Json            
        }
        catch {
            if (-not $_.Exception.Response) {
                Write-ErrorLog "An error occurred while making the request:`n`n$($_.Exception.Message)"
            }
            else {
                if ($refreshToken -and $_.Exception.Response.StatusCode.value__ -eq 401) {
                    $token = RefreshBearerToken

                    if ($token -ne $null) {
                        Write-DebugLog "Updated access token: $token"

                        $script:accessToken = $token
                        $arguments["Headers"]["Authorization"] = "Bearer $token"
                        $refreshToken = $false

                        continue
                    }
                    
                    $token = RefreshAuthToken
                    
                    if ($token -ne $null) {
                        Write-DebugLog "Updated auth token: $token"

                        $script:accessToken = $token
                        $arguments["Headers"]["Authorization"] = "Token $token"
                        $refreshToken = $false

                        continue
                    }
                }
                
                Write-ErrorLog "An error occurred while making the request:`n`n$($_.Exception.Response.StatusDescription) (Status code: $($_.Exception.Response.StatusCode.value__))"
            }        

            throw
        }
        finally {
            $ProgressPreference = $currentProgressPreference
        }
    }
    while ($true)
}

function RefreshBearerToken() {
    $token = GetToken

    if (-not $token.bearerToken) {
        return $null
    }

    if (-not $token.refreshToken) {
        return $null
    }

    Write-DebugLog "Refreshing the bearer token"

    $uri = CreateUrl -endpoint "/token" -kind "MO"
    $headers = CreateHeaders -kind "MO"
    $body = (@{ "refreshToken" = $token.refreshToken }) | ConvertTo-Json -Compress

    $response = InvokeRestMethod -uri $uri -method "POST" -headers $headers -body $body -refreshToken $false

    return $response
}

function RefreshAuthToken(){
    $token = GetToken

    if ($token.bearerToken) {
        return $null
    }

    Write-DebugLog "Refreshing the token token"

    $config = GetConfig
    
    $uri = CreateUrl -endpoint "/auth" -kind "DAM"
    $headers = CreateHeaders -kind "DAM" -additionalHeaders @{ "Authorization" = ($config.authorization); "Registration" = ($config.registration) }

    $response = InvokeRestMethod -uri $uri -headers $headers -refreshToken $false

    return $response.token;
}

function GetVersion {
    return $script:version
}

function GetUserAgent {
    if ($script:userAgent -ne $null) {
        return $script:userAgent
    }

    $version = GetVersion
    
    $psVersion = $PSVersionTable.PSVersion
    $productName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
    $buildVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
    $architecture = if ([IntPtr]::Size -eq 8) { "x64" } else { "x86" }

    return "Aprimo.Hotfolder.Service/$version (PowerShell $psVersion; $productName Build $buildVersion; $architecture)"
}

function GetConfig {
    if (-not ($script:appSettings -eq $null)) {
        return $script:appSettings
    }

    $path = Resolve-Path (Join-Path $PSScriptRoot "../app.config")

    $script:appSettings = @{}
    $config = [xml](Get-Content $path)
    foreach ($node in $config.configuration.appsettings.add) {
        $script:appSettings[$node.key] = $node.value
    }

    return $script:appSettings
}

function CombineUrlSegments([string[]]$parts) {
    return ($parts | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim("/") } | Where-Object { $_ }) -join "/"
}

function CreateUrl([string]$endpoint, [ValidateSet("DAM", "MO", IgnoreCase = $true)][string]$kind) {
    $config = GetConfig

    $url = $config.endpointUri

    switch ($Kind) {
        "DAM" {
            if ($url -match "dam\.(labs\.)?aprimo\.com\/?$") {
                return CombineUrlSegments $url, "api/core", $endpoint
            }
            elseif ($Url -match "(labs\.)?aprimo\.com\/?$") {
                return CombineUrlSegments ($url -replace "(labs\.)?aprimo\.com", "dam.`$1aprimo.com"), "api/core", $endpoint
            }

            return CombineUrlSegments $url, "api/core", $endpoint
        }

        "MO" {
            if ($url -match "dam\.(labs\.)?aprimo\.com\/?") {
                return CombineUrlSegments ($url -replace "dam\.(labs\.)?aprimo\.com", "`$1aprimo.com"), "api", $endpoint
            }

            return CombineUrlSegments $url, "api", $endpoint
        }
    }
}

function CreateHeaders([Parameter(Mandatory = $true)][ValidateSet("MO", "DAM", IgnoreCase = $true)][string]$kind, [Parameter(Mandatory = $false)][Hashtable]$additionalHeaders = $null) {
    $headers = @{}

    $config = GetConfig
    $token = GetToken

    switch ($kind) {
        "MO" {
            $headers = @{
                "client-id"     = $config.clientId
                "Content-Type"  = "application/json; charset=utf-8"
                "Authorization" = $config.authorization
                "User-Agent"    = (GetUserAgent)
            }
        }

        "DAM" {
            $prefix = "Bearer"
            if (-not $token.bearerToken) {
                $prefix = "Token"
            }
            
            $headers = @{
                "API-Version"   = "1"
                "Accept"        = "application/json"
                "Content-Type"  = "application/json; charset=utf-8"
                "Authorization" = "$prefix $($token.accessToken)"
                "User-Agent"    = (GetUserAgent)
            }
        }
    }

    if ($additionalHeaders -ne $null) {
        foreach ($header in $additionalHeaders.Keys) {
            $headers[$header] = $additionalHeaders[$header]
        }
    }

    return $headers
}

function GetFileSize([string]$path) {
    return (Get-ItemProperty -LiteralPath $path).Length
}

function GetToken() {
    return $script:token
}

function BuildJson([string]$filename){
$json = @"
{
    "FileName":"$filename"
}
"@
    return $json
}

function CompareEncodedFileNames ([string]$filename) {
    $utfEnc = [System.Text.Encoding]::GetEncoding("UTF-8")
    $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")

    $isoBytes = $enc.Getbytes($filename)
    $utfBytes = $utfEnc.Getbytes($filename)
    
    $diff = Compare-Object -ReferenceObject $isoBytes -DifferenceObject $utfBytes -PassThru 

    return ($diff.length -gt 0)
}

function UploadFile([string]$path) {
    $fileSize = GetFileSize $path

    $humanReadableFilesSize = GetHumanReadableFileSize $fileSize
    Write-DebugLog "Uploading $path ($humanReadableFilesSize)..."

    $filename = Split-Path $path -Leaf
    $mimeType = GetMimeType $path
    $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")

    $segmented = $fileSize -gt $threshold
    if(-not $segmented)
    {
        # Since there are encoding issues with single file upload from powershell, we compare the file names here.
        # If the encoded byte arrays are the same then there are no special characters in the filename and all okay, otherwise we use segmented upload.
        # note: Segmented upload sends filename serpeately in "prepare" function to resolve this issue.
        $segmented = CompareEncodedFileNames -filename $filename    
    }    
    $fileStream = OpenFile -path $path    

    try {
        if (-not $segmented){
            Write-Progress -Id 2 -ParentId 1 -Activity "Uploading $filename ($humanReadableFilesSize)" -PercentComplete 0

            $data = ReadFile -fileStream $fileStream -offset 0 -count $fileSize
            $result = (UploadData -uri (CreateUploadUri -endpoint "/uploads") -name "file1" -filename $filename -mimeType $mimeType -data ($enc.GetString($data)) | ParseUploadResult)

            Write-Progress -Id 2 -ParentId 1 -Activity "Uploading $filename ($humanReadableFilesSize)" -PercentComplete 100

            return $result
        }
        else {
            $headers = CreateHeaders -kind "DAM"

            $json = BuildJson -filename $filename
            $response = InvokeRestMethod -uri (CreateUploadUri -endpoint "/uploads/segments") -method "POST" -headers $headers -body $json

            $uri = $response.uri
            [long]$segment = 0
            [long]$offset = 0
            [long]$bytesLeft = $fileSize
 
            try {
                while ($bytesLeft -gt 0) {
                    Write-Progress -Id 2 -ParentId 1 -Activity "Uploading $filename ($humanReadableFilesSize)" -PercentComplete ((($fileSize - $bytesLeft) / $fileSize) * 100)
 
                    [long]$count = [math]::Min($threshold, $bytesLeft)
 
                    $data = ReadFile -fileStream $fileStream -offset $offset -count $count
                    UploadData -uri ($uri + "?index=$segment") -name "segment$segment" -filename "$filename.segment$segment" -mimeType $mimeType -data ($enc.GetString($data)) | Out-Null
                                    
                    $bytesLeft -= $count
                    $offset += $count
                    $segment++
                }
            }
            catch {
                Write-DebugLog "Deleting the uploaded segments of $filename ($uri)"
                DeleteUploadedFile -uri $uri
                throw
            }

            Write-Progress -Id 2 -ParentId 1 -Activity "Uploading $filename ($humanReadableFilesSize)" -PercentComplete 100

            Write-Progress -Id 2 -ParentId 1 -Activity "Finalizing upload"

            $body = @{
                filename     = $filename
                segmentcount = $segment
            } | ConvertTo-Json -Compress

            return (InvokeRestMethod -uri (CombineUrlSegments $uri, "commit") -method "POST" -headers $headers -body $body | ParseUploadResult)
        }
    }
    finally {
        CloseFile $fileStream
    }
}

function CreateUploadUri([string]$endpoint) {
    $config = GetConfig

    if ($config.ContainsKey("uploadserviceUri") -and $config["uploadserviceUri"]) {
        Write-DebugLog "Using the upload servie to handle a file"

        return CombineUrlSegments $config["uploadserviceUri"], $endpoint
    }
    else {
        Write-DebugLog "Using the REST api to handle a file"

        return CreateUrl -endpoint $endpoint -kind "DAM"
    }
}
function UploadMetadataFile([string]$path, [hashtable]$metadataFileTable){

    Write-InfoLog "Start upload metadata file '$path'"

    $token = UploadFile -path $path
    $metadataFileTable.Add($path, $token)
}

function CreateBoundary {
    return "----Boundary$((Get-Date).ToUniversalTime().ToString("1MMdd-1HHmm"))"
}

function UploadData([string]$uri, [string]$name, [string]$filename, [string]$mimeType, [string]$data) {
    $template = @"
--{0}
Content-Disposition: form-data; name=`"{1}`"; filename=`"{2}`"
Content-Type: {3}

{4}
--{0}--
"@

    $boundary = CreateBoundary

    $headers = CreateHeaders -kind "DAM" -additionalHeaders @{ "Content-Type" = "multipart/form-data; boundary=$boundary" }
    
    $body = $template -f $boundary, $name, $filename, $mimeType, $data

    return InvokeRestMethod -uri $uri -method "POST" -headers $headers -body $body
}

function ParseUploadResult([Parameter(ValueFromPipeline = $true)]$response) {
    if ($response.token) {
        return $response.token
    }

    $uri = $response.uri
    $headers = CreateHeaders -kind "DAM"

    do {
        $response = InvokeRestMethod -uri $uri -headers $headers
        if ($response.token) {
            return $response.token
        }

        Start-Sleep -Milliseconds 1000
    }
    while ($true)
}

function OpenFile([string]$path) {
    return [System.IO.File]::OpenRead((Resolve-Path $path).ProviderPath)
}

function ReadFile($fileStream, $offset, $count) {
    $bytes = New-Object -TypeName Byte[] -ArgumentList $count

    $fileStream.Seek($offset, "Begin") | Out-Null
    $fileStream.Read($bytes, 0, $count) | Out-Null

    return $bytes
}

function CloseFile($fileStream) {
    $fileStream.Close()
}

function GetMimeType([string]$path) {
    Add-Type -AssemblyName System.Web

    $mimeType = [System.Web.MimeMapping]::GetMimeMapping($path)
            
    if ($mimeType) {
        return $mimeType
    }
    
    return "application/octet-stream"
}

function CreateClassificationTree([string]$rootId, [string[]]$classificationNames) {
    if (!$classificationNames -or ($classificationNames.Count -eq 0)) {
        return $rootId
    }
    
    Write-DebugLog "Retrieving the classification id using root $rootId and path $($classificationNames -join "/")"

    $uri = CreateUrl -endpoint "/classifications" -kind "DAM"

    $id = $rootId
    foreach ($classificationName in $classificationNames) {
        $headers = CreateHeaders -kind "DAM"
        $filter = [System.Web.HttpUtility]::UrlEncode("parent.id = '$id' and name = '$classificationName'")

        $response = InvokeRestMethod -uri "$($uri)?filter=$($filter)" -method "GET" -headers $headers
        if ($response.items -and $response.items.Count -ne 0) {
            $id = $response.items[0].id
            continue
        }

        Write-Progress -Id 2 -ParentId 1 -Activity "Creating the classification tree"

        $headers = CreateHeaders -kind "DAM" -additionalHeaders @{ "set-immediateSearchIndexUpdate" = "true" }
        $response = InvokeRestMethod -uri $uri -method "POST" -headers $headers -body (@{
                name     = $classificationName
                parentId = $id
            } | ConvertTo-Json -Compress)

        $id = $response.id
        
        Write-InfoLog "Created classification with name $classificationName"
    }

    return $id
}

function GetFilesWithBaseName([string]$path) {
    $item = Get-Item $path
    $baseName = $item.BaseName
    $directoryName = $item.DirectoryName

    return (Get-ChildItem -Path "$directoryName\$baseName.*" -Attributes !Directory+!System+!Hidden | ForEach-Object { $_.FullName })
}

#endregion

#region Exported functions

function Add-Types {
    [CmdletBinding()]
    param()

    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Aprimo.HotfolderService {
    public static class Win32 
    {
        public static long FormatByteSize(long fileSize, StringBuilder buffer)
        {
            return StrFormatByteSize(fileSize, buffer, buffer.Capacity);
        }

        [DllImport("Shlwapi.dll", CharSet = CharSet.Auto)]
        private static extern long StrFormatByteSize(long fileSize, System.Text.StringBuilder buffer, int bufferSize);
    }

    public enum LogLevel 
    {
        None = 0,
        Error = 1,
        Warn = 2,
        Info = 4,
        Debug = 5
    }
}
"@

    Write-DebugLog "Types added"
}

function Initialize-Session {
    [CmdletBinding()]
    param()

    $config = GetConfig

    if ($config.endpointUri -match "^https") {
        # Need to explicitly set the protocol to use TLS 1.2 if the endpoint uri is https
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    if ($config.ContainsKey("clientId") -and $config["clientId"]) {
        Write-DebugLog "Using the MO api to create a session"

        # A client-id was specified, this indicates MO authentication is to be used
        $headers = CreateHeaders -kind "MO"
        $uri = CreateUrl -endpoint "/oauth/create-native-token" -kind "MO"

        $response = InvokeRestMethod -uri $uri -headers $headers -method "POST" -refreshToken $false
        $script:token = @{
            accessToken  = $response.accessToken
            refreshToken = $response.refreshToken
            bearerToken  = $true
        }

        $sb = New-Object System.Text.StringBuilder
        [void] $sb.AppendLine("Tokens:")
        [void] $sb.AppendLine("  Access token: $($script:token.accessToken)")
        [void] $sb.Append("  Refresh token: $($script:token.refreshToken)")
        
        Write-DebugLog ($sb.ToString())
    }
    else {
        Write-DebugLog "Using the DAM api to create a session"

        $headers = CreateHeaders -kind "DAM" -additionalHeaders @{ "Authorization" = ($config.authorization); "Registration" = ($config.registration) }
        $uri = CreateUrl -endpoint "/auth" -kind "DAM"

        $response = InvokeRestMethod -uri $uri -headers $headers -refreshToken $false

        $script:token = @{
            accessToken  = $response.token
            refreshToken = ""
            bearerToken  = $false
        }

        Write-DebugLog "Access token: $($script:token.accessToken)"
    }
}

function Get-FileList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [string]
        $FailedFilesFolder
    )

    $fileTable = @{}

    [array]$directories = Get-DirectoryList -Path $Path

    

    foreach ($directory in $directories) {

        [array]$files = Get-DirectoryContents -Path $directory.FullName -Verbose:($PSBoundParameters['Verbose'] -eq $true)

        $singleMetadataFiles = @{}
        $genericMetadataFiles = New-Object System.Collections.ArrayList

        # weird empty folder issue. When no files it sometimes still iterates through files
        if($files.Count -eq 0){
            continue;
        }

        # First iterate for the metadata and normal file speration
        # and to get a full metadata list
        foreach ($file in $files) {
            
            if($file.Extension -eq ".csv") {
                $singleMatch = $false
                foreach ($inner in $files) {
                    if($inner.Extension -ne ".csv" -and $inner.BaseName -eq $file.BaseName){
                        
                        $singleMetadataFiles.Add($file.BaseName, $file.FullName);
                        $singleMatch = $true
                        break
                    }
                }
                
                if($singleMatch -eq $false){
                    [void]$genericMetadataFiles.Add($file.FullName)
                }
            }
        }

        $failedFolder = $genericMetadataFiles.Count -gt 1
        $filePath = ""
        $subFoldersStr = ""
        # When multiple generic metadata files cannot determine what to use. 
        # skip folder instead. Problem is that once uploaded you cannot undo so correct this situation first
        if ($failedFolder -eq $true){

            Write-WarningLog "Multiple metadata files found in folder '$($directory.FullName)'. Skipped uploading files in this folder."
            $filePath = $file.FullName -replace [regex]::escape($Path), ""
            $subFoldersStr = (Split-Path -Path $filePath)
            
            $genericMetafilesList = $genericMetadataFiles -join ', '
            Write-WarningLog "Conflicting metadata files: $genericMetafilesList"

            foreach ($file in $files){
                if ($failedFolder -eq $true){

                    $filePath = $file.FullName -replace [regex]::escape($Path), ""
                    $subFoldersStr = (Split-Path -Path $filePath)
                    
                    AddToFailedFolder -Path $file.FullName -FailedFilesFolder $FailedFilesFolder -SubFolders $subFoldersStr
                }
            }

            # Skip to next directory
            continue
        }
        
        # Fill the fileTable with files and their possible metadata files
        foreach ($file in $files | Where-Object {$_.Extension -ne ".csv"} ) {
            
            $metaFile = ""
            
            if($singleMetadataFiles.ContainsKey($file.BaseName)){
                
                $metaFile = $singleMetadataFiles.Get_Item([string]$file.BaseName)
            }
            elseif ($genericMetadataFiles.Count -eq 1){
                $metaFile = [string]$genericMetadataFiles[0];
            }
            
            $fileTable.Add($file.FullName, $metaFile)
        }

    }
    
    return $fileTable

}

function Get-DirectoryList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Path
    )

    # include the given Path folder
    return Get-ChildItem $Path -Recurse -Directory -Attributes !System+!Hidden | foreach-object -begin { $arr = @((Get-Item $Path)) } -process { $arr+= $_ } -end { $arr }
}

function Get-DirectoryContents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $Path
    )

    return (Get-ChildItem -Path $Path -Attributes !Directory+!System+!Hidden)
}

function New-Record {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $Classification,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]
        $SubClassifications,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $MetaDataFileToken,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]
        $MetaDataSchemaName
    )

    $uploadToken = UploadFile -path $Path
    Write-DebugLog "Got upload token $uploadToken"

    try{
        $createdItem = "draft"
        $classificationId = $null
        if ($Classification) {
            $createdItem = "record"
            $classificationId = CreateClassificationTree -rootId $Classification -classificationNames $SubClassifications
        }
    
        $filename = Split-Path -Path $Path -Leaf
    
        $url = CreateUrl "/records" -Kind "DAM"
        $headers = CreateHeaders -kind "DAM"
        $body = (CreateBody -classificationId $classificationId -uploadToken $uploadToken -MetaDataFileToken $MetaDataFileToken -MetaDataSchemaName $MetaDataSchemaName -filename $filename | ConvertTo-Json -Depth 99 -Compress)
    
        Write-Progress -Id 2 -ParentId 1 -Activity "Creating the record"
    
        $response = InvokeRestMethod -uri $url -method "POST" -headers $headers -body $body
    
        Write-InfoLog "Created $createdItem with file ($filename)"
        Write-DebugLog "Created $createdItem with id $($response.id)"
    }
    catch {        
        # error during create new record, clean up the uploaded file
        Write-DebugLog "Deleting the uploaded file: $filename"
        $response = DeleteUploadedFile -uri (CreateUploadUri -endpoint "/uploads/$uploadToken")
        throw
    }
}

function DeleteUploadedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $uri
    )

    $headers = CreateHeaders -kind "DAM"
    return  InvokeRestMethod -uri $uri -method "DELETE" -headers $headers
}

function CreateBody([string]$classificationId, [string]$uploadToken, [string]$metaDataFileToken, [string]$metaDataSchemaName, [string]$filename) {

    $body = (@{
            "files"           = @{
                "master"      = $uploadToken
                "addOrUpdate" = @(
                    @{
                        "versions" = @{
                            "addOrUpdate" = @(
                                @{
                                    "id"       = $uploadToken
                                    "filename" = $filename
                                }
                            )
                        }
                    }
                )
            }
        })

    # no classificatio id is defined
    if (!$ClassificationId) {
        $body.add("status", "draft")
    } else {
        $body.add("classifications", @{
                "addOrUpdate" = @(
                    @{
                        "id" = $classificationId
                    }
                )
            })
    }
    if($metaDataFileToken -and $metaDataSchemaName){
        $body.add("metadata", @{
            "name" = $metaDataSchemaName
            "token" = $metaDataFileToken
        })
    }

    return $body
}

function Remove-ProcessedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Nothing", "DeleteFile", "DeleteBase", IgnoreCase = $true)]
        [string]
        $ActionOnSuccess
    )

    switch ($ActionOnSuccess) {
        "Nothing" {

        }

        "DeleteFile" {
            Write-DebugLog "Deleting $Path..."
            Remove-Item -Path $Path -Force
        }

        "DeleteBase" {
            foreach ($item in (GetFilesWithBaseName -path $Path)) {
                Write-DebugLog "Deleting $item..."
                Remove-Item -Path $item -Force
            }
        }
    }
}

function AddToFailedFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Path,
        
        [Parameter(Mandatory = $false)]
        [string]
        $FailedFilesFolder,

        [Parameter(Mandatory = $false)]
        [string]
        $SubFolders
    )
    if ($FailedFilesFolder) {
        Write-DebugLog "Moving $Path to $FailedFilesFolder..."

        try {
            $dest = $FailedFilesFolder
            if($SubFolders){
                $dest = (Join-Path $FailedFilesFolder $SubFolders)
            }
            
            if (-not (Test-Path $dest)) {
                New-Item -Path $dest -ItemType Directory | Out-Null
            }

            Move-Item -Path $Path -Destination $dest -Force
        }
        catch {
            Write-ErrorLog "An error occurred while moving the file to the failed files folder`n`n$($_.Exception.Message)"
        }
    }
}

function Start-Log {
    [CmdletBinding()]
    param()

    $config = GetConfig

    $now = Get-Date

    $logDir = $config.logDir
    if (-not $logDir) {
        return
    }

    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory | Out-Null
    }
    
    $path = Join-Path $logDir "$($now.ToString("yyyy-MM-dd")).txt"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType File | Out-Null
    }

    Start-Transcript -Path $path -Append -NoClobber
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]
        $Message,

        [Parameter()]
        [ValidateSet("None", "Error", "Warn", "Info", "Debug", IgnoreCase = $true)]
        [string]
        $Level
    )

    $config = GetConfig

    $logLevel = [Aprimo.HotfolderService.LogLevel] $Level
    $configuredLevel = [Aprimo.HotfolderService.LogLevel] ($config.logLevel)

    if ($logLevel.value__ -gt $configuredLevel.value__) {
        return
    }

    $timestamp = (Get-Date).ToUniversalTime().ToString("o")

    Write-Host "$timestamp $($Level.ToUpper()) $Message`r`n"
}

function Write-ErrorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]
        $Message
    )

    Write-Log $Message -Level "Error"
}

function Write-WarningLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]
        $Message
    )

    Write-Log $Message -Level "Warn"
}

function Write-InfoLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]
        $Message
    )

    Write-Log $Message -Level "Info"
}

function Write-DebugLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]
        $Message
    )
    Write-Log $Message -Level "Debug"
}

function Stop-Log {
    [CmdletBinding()]
    param()

    Stop-Transcript
}

#endregion

Export-ModuleMember -Function Add-Types, Initialize-Session, Get-FileList, Get-DirectoryList, Get-DirectoryContents, New-Record, CreateUploadUri, UploadFile, UploadMetadataFile, DeleteUploadedFile, Remove-ProcessedFile, AddToFailedFolder, Start-Log, Write-Log, Stop-Log, Write-ErrorLog, Write-WarningLog, Write-InfoLog, Write-DebugLog
