<!-- Last updated 08 November 2019 -->
# Introduction
Represents a PowerShell script to upload the contents of a directory to the Aprimo DAM and to create a record for each file.

# Requirements
- [PowerShell 3 or higher](https://www.microsoft.com/en-us/download/details.aspx?id=50395)

# Running the script
## Configuration
Prior to running the script, it needs to be configured. To that end, edit the *app.config* file and fill in the following values:
| Name | Description |
| ---: | --- |
| endpointUri | The uri to your MO/ADAM installation, e.g. *https://mycompanyname.aprimo.com* |
| uploadserviceUri | The endpoint uri to the upload service, e.g. *https://mycompanyname.aprimo.com/uploads* |
| clientId | The client-id, as created in Marketing Operations |
| authorization | The Base-64 Encoded Authorization Code, make sure to include the prefix, e.g. *Basic [Base64 encoded string]* |
| logDir | The directory where the log files are written |
| logLevel | The log level, valid values are *None*, *Error*, *Warn*, *Info*, *Debug* |

For information on how to create a client-id and authorization code see [the Authorization section](https://developers.aprimo.com/marketing-operations/rest-api/authorization/#module3) of the Marketing Operations REST API [documentation](https://developers.aprimo.com/marketing-operations/rest-api/).

## Executing the script
```ps
.\Aprimo.HotFolderService.ps1 -Path value [-Classification value] [-ClassifySubFolders] -ActionOnSuccess <Nothing|DeleteFile|DeleteBase> [-FailedFilesFolder value]
```

| Parameter | Description |
| ---: | --- |
| -Path | The path to the folder to scan |
| -Classification | (Optional) When specified, the GUID of the root classification under which to create new records. Otherwise the files are uploaded as draft. |
| -ClassifySubFolders | (Optional) Indicates whether to create classifications of sub folders. Ignored when upload as draft |
| -ActionOnSuccess | Indicates what should happen to the file after it has been successfully created.<br/>One of the following values: Nothing, DeleteFile, DeleteBase<br/><br/>Nothing - Leaves the file in place.<br/>DeleteFile - Deletes the file.<br/>DeleteBase - Deletes all files with the same base name. |
| -FailedFilesFolder | (Optional) When specified, indicates to where files are being moved that failed to upload |
| -MetaDataFile | (Optional) The path to a metadata CSV file. When specified, in combination with parameter -MetaDataSchemaName, the server will use this metadata file to extract metadata for each uploaded file. |
| -MetaDataSchemaName | (Optional) When specified, the server will use this schema name to find a schema definition from the .dataExchangeSchemas setting. This parameter is required if you want the script to pick metadata CSV files from your folder automatically. |