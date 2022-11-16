from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
import base64

KVUri = "https://" + "gevault2" + ".vault.azure.net"

credential = DefaultAzureCredential(connection_verify=False, exclude_shared_token_cache_credential=True)

# certificate_client = CertificateClient(vault_url=KVUri, credential=credential)

# certificate = certificate_client.get_certificate("edisoniotdevedgeinterca1")

# print(certificate.name)
# print(certificate._properties)
# print(certificate.policy.issuer_name)

secret = SecretClient(vault_url= KVUri,credential= credential,connection_verify=False)
secret_client = secret.get_secret("edisoniotdevedgeinterca4")
secret_b64 = base64.b64decode(secret_client.value)
with open('test.pfx','wb') as fopen:
    fopen.write(secret_b64)