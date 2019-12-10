# HotFolderUpload

This PowerShell script allows you to upload files from a folder to Aprimo DAM. The script can be executed manually or you could use a service such as the Windows Task Scheduler. This script is not executed in the Azure environment but runs on a local server.

For the upload, the script will use the MO REST API (for authentication) and the Aprimo DAM REST API.

Transfers occur over HTTP and will be limited by the upload bandwidth you have available. If you have concerns about ingesting large sets (>10GB) of assets, please contact your Aprimo representative to discuss ingestion options.
