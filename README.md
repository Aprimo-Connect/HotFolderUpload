# PowerShell Script for Uploading Files to Aprimo DAM

### Aprimo's Open Source Policy 
This code is provided by Aprimo _as-is_ as an example of how you might solve a specific business problem. It is not intended for direct use in Production without modification.

You are welcome to submit issues or feedback to help us improve visibility into potential bugs or enhancements. Aprimo may, at its discretion, address minor bugs, but does not guarantee fixes or ongoing support.

It is expected that developers who clone or use this code take full responsibility for supporting, maintaining, and securing any deployments derived from it.

If you are interested in a production-ready and supported version of this solution, please contact your Aprimo account representative. They can connect you with our technical services team or a partner who may be able to build and support a packaged implementation for you.

Please note: This code may include references to non-Aprimo services or APIs. You are responsible for acquiring any required credentials or API keys to use those services—Aprimo does not provide them.
## Overview
This PowerShell script is an open-source example for uploading files to Aprimo DAM. It is not part of Aprimo's official product or support, and you can modify it to fit your use case. The script runs on a local server and uses the **REST API** for authentication and uploads. Transfers occur over HTTP and are limited by your available upload bandwidth. For large uploads (>10GB), contact your Aprimo representative.

## Requirements
- **PowerShell**: Version 4–6 (Windows only).

## Download
Get the script from [GitHub](https://github.com/Aprimo-Connect/HotFolderUpload).

## Configuration
Add the following details to the `app.config` file for the script to work:
- **Aprimo DAM URL**
- **Upload Service URL**
- **Client ID**
- **Client Secret**

Example `app.config` file:
```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="endpointUri" value="https://yourcompany.dam.aprimo.com" />
    <add key="uploadserviceUri" value="https://yourcompany.aprimo.com" />
    <add key="clientId" value="[Client ID]" />
    <add key="clientSecret" value="[Client Secret]" />
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
