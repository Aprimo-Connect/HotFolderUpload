# PowerShell Script for Uploading Files to Aprimo DAM

## Aprimo's Open Source Policy 
This code is provided by Aprimo as-is to serve as an example of how you might solve a particular business problem. It is not intended to be deployed directly into Production. You may submit issues with the code, however, Aprimo may not provide fixes. It is expected that the consumer of this code will take on responsibility to support any deployments or executions of this code. If you would like Aprimo to provide a packaged solution for what this code provides, please reach out to your account contact, who can connect you with our technical services team or another partner that might be able to create a production-ready and production supported solution for you. This code may call out to other non-Aprimo services, and you may need your own API keys or access to those services as well, which Aprimo does not provide.

## Overview
This PowerShell script is an open-source example for uploading files to Aprimo DAM. It is not part of Aprimo's official product or support, and you can modify it to fit your use case. The script runs on a local server and uses the **REST API** for authentication and uploads. Transfers occur over HTTP and are limited by your available upload bandwidth. For large uploads (>10GB), contact your Aprimo representative.

## Requirements
- **PowerShell**: Version 4–6 (Windows only).

## Download
Get the script from [GitHub](https://github.com/Aprimo-Connect/HotFolderUpload).

## Configuration
Add the following details to the `app.config` file for the script to work:
- **Aprimo DAM URL**
- **Client ID**
- **Authentication token**

Example `app.config` file:
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="endpointUri" value="https://yourcompany.dam.aprimo.com" />
    <add key="uploadserviceUri" value="https://yourcompany.aprimo.com" />
    <add key="authorization" value="[Auth Token]" />
    <add key="clientId" value="[Client ID]" />
    <add key="logDir" value="C:\scriptlog" />
    <add key="logLevel" value="Info" />
  </appSettings>
</configuration>
```
The app config file also contains two keys for logging:
- logDir: The destination folder for the log files.
- logLevel: The log level. Valid values are None, Error, Warn, Info, Debug.

## Script Execution

```powershell
Aprimo.HotFolderService.ps1 -Path C:\hotfolder -Classification {classicationID} -ClassifySubFolders -ActionOnSuccess DeleteFile -FailedFilesFolder C:\failed -MetaDataFile "C:\HotFolder\metadata.csv" -MetaDataSchema "example1"
```

## Parameters

| Parameter | Type | Required | Default Value |Description |
|-----------|------|----------|---------------|------------|
| `-Path`   | String | Yes | None | Folder path to scan for files.|
| `-Classification`   | String | No | None | Classification ID to link new records. Avoid overlapping classifications.|
| `-ClassifySubFolders`   | Switch | No | False | Creates a classification structure based on folder hierarchy.  |
| `-ActionOnSuccess`    | String | Yes | None | Action after a successful upload. Options: `Nothing`, `DeleteFile`, `DeleteBase`. |
| `-FailedFilesFolder`   | String | No | None | Folder to move failed uploads.   |
| `-MetaDataFile`   | String | No | None | Path to a CSV file containing metadata. |
| `-MetaDataSchemaName`  | String | No | None | Schema to parse metadata. |

:::tip
**MetaDataSchemaName**: See Metadata Upload for more information.
:::

## How It Works
- Folder Scan: Scans the root folder (and subfolders) for files.
- Record Creation:
    - Links records to the classification specified by Classification.
    - Uses the ClassifySubFolders parameter to create classifications based on folder names.
    - Creates draft records if no classification is specified.
- Metadata Mapping: Maps metadata from the provided CSV file.
- File Handling: Processes files based on the ActionOnSuccess parameter.
- Failed Uploads: Keeps failed files in the folder or moves them to FailedFilesFolder.

## Metadata Upload

You can associate metadata with uploaded files in three ways:
- Pass the metadata file path as a script parameter.
- Add a metadata file with the same base name as the file to upload.
- Use a single metadata file for all files in a folder.

## Metadata Upload Logic

- Checks for the metadata file path in script parameters.
- Searches for a metadata file with the same base name as the uploaded file.
- Uses a generic metadata file in the folder if available. If multiple generic metadata files exist, the file is placed in the Failed Files folder.
