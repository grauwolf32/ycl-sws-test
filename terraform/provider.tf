# Credentials and the destination cloud/folder are deliberately read from
# YC_TOKEN (or YC_SERVICE_ACCOUNT_KEY_FILE), YC_CLOUD_ID and YC_FOLDER_ID.
# Keeping them out of HCL makes the resulting configuration reusable.
provider "yandex" {}
