from azure.identity import DefaultAzureCredential,EnvironmentCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
import base64
import os

# KVUri = "https://" + "gevault2" + ".vault.azure.net"
# KVUri=os.getenv("VAULT_URL",default=None)
KVUri=os.environ.get("VAULT_URL")
print(KVUri)
# credential = DefaultAzureCredential(connection_verify=False, exclude_shared_token_cache_credential=True)
# client = CertificateClient(vault_url= KVUri,credential= credential,connection_verify=False)
# client =SecretClient(vault_url=KVUri, credential=credential)
cert_name=input("Enter Certificate Name: ")

cert_pfx=cert_name+".pfx"
key_pfx="secret.pfx"
print(cert_pfx)
# cert=client.get_secret(name=cert_name,version="x509-cert")
# cert_byte=base64.decodebytes(cert)
# with open(cert_pfx,'wb') as fopen:
#         fopen.write(cert_byte)
# client_cert = client.get_certificate(cert_name,"x509-cert")
try:
    credential =EnvironmentCredential()
    client = CertificateClient(vault_url= KVUri,credential= credential,connection_verify=False)
    secret_client =SecretClient(vault_url=KVUri, credential=credential)
    client_cert = client.get_certificate_version(certificate_name=cert_name, version="x509-cert")
    cert_byte = client_cert.cer
    with open(cert_pfx,'wb') as fopen:
        fopen.write(cert_byte)
    secret = secret_client.get_secret(name=cert_name)
    b64 = base64.b64decode(secret.value)
    with open(key_pfx,'wb') as kpfx:
            kpfx.write(b64)
except Exception as ex:
    print("no such file in vault")
