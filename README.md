# HotFolderUpload

This PowerShell script allows you to upload files from a folder to Aprimo DAM. The script can be executed manually or you could use a service such as the Windows Task Scheduler. This script is not executed in the Azure environment but runs on a local server.

This Powershell script to upload files from Powershell into Aprimo is an open source example and not part of Aprimo product & support. You can freely change the script to fit your usecase.

For the upload, the script will use the MO REST API (for authentication) and the Aprimo DAM REST API.

Transfers occur over HTTP and will be limited by the upload bandwidth you have available. If you have questions, please see the additional documentation at [the Aprimo developers site](https://developers.aprimo.com/digital-asset-management/powershell-script-file-uploads/)
