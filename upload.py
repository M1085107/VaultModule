from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import (
    CertificateClient,
    CertificateContentType,
    CertificatePolicy,
    WellKnownIssuerNames,
)
from azure.keyvault.secrets import SecretClient
import base64

KVUri = "https://" + "pevault2" + ".vault.azure.net"

credential = DefaultAzureCredential(connection_verify=False, exclude_shared_token_cache_credential=True)
client = CertificateClient(vault_url= KVUri,credential= credential,connection_verify=False)

cert_name = input("Enter Certificate name:")
cert_pass=input("Enter the password: ")
# uploading pfx
pfx_name=cert_name+".pfx"
try:
    with open('./certs/'+pfx_name, 'rb') as f:
        pfx_cert_bytes = f.read()

    imported_pfx=client.import_certificate(certificate_name= cert_name,certificate_bytes=pfx_cert_bytes , password=cert_pass)
    print("PFX certificate imported successfully.".format(imported_pfx.name))
except Exception as ex:
    print(ex)

# #uploading pem
# pem_name=cert_name+".pem"
# try:
#     with open('./certs/'+pem_name, 'rb') as f:
#         pem_cert_bytes = f.read()

#     pem_policy=CertificatePolicy(issuer_name=WellKnownIssuerNames.self, content_type=CertificateContentType.pem)
#     imported_pem = client.import_certificate(
#         certificate_name=pem_name, certificate_bytes=pem_cert_bytes, policy=pem_policy
#     )
#     print("PEM-formatted certificate  imported successfully.".format(imported_pem.name))
# except Exception as ex:
#     print("Unable to upload pem file on vault")