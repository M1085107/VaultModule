from azure.identity import DefaultAzureCredential,EnvironmentCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
import base64
import os
import OpenSSL.crypto as crypto

# KVUri = "https://key-edge-dev-infra-001.vault.azure.net/"
# KVUri=os.getenv("VAULT_URL",default=None)
KVUri=os.environ.get("VAULT_URL")
print(KVUri)
# credential = DefaultAzureCredential(connection_verify=False, exclude_shared_token_cache_credential=True)
# client = CertificateClient(vault_url= KVUri,credential= credential,connection_verify=False)
# client =SecretClient(vault_url=KVUri, credential=credential)
cert_name=input("Enter Certificate Name: ")

cert_pfx=cert_name+".pfx"
print(cert_pfx)
# cert=client.get_secret(name=cert_name,version="x509-cert")
# cert_byte=base64.decodebytes(cert)
# with open(cert_pfx,'wb') as fopen:
#         fopen.write(cert_byte)
# client_cert = client.get_certificate(cert_name,"x509-cert")
try:
    credential =EnvironmentCredential()
    client = SecretClient(vault_url= KVUri,credential= credential,connection_verify=False)
    client_cert = client.get_secret(name=cert_name, version="x509-cert")
    # cert_crypto = crypto.load_certificate(crypto.FILETYPE_PEM,client_cert)
    # public_key=cert_crypto.get_pubkey()
    # private_key=crypto.dump_privatekey(crypto.FILETYPE_PEM, public_key)
    # print(private_key)
    
    # client = CertificateClient(vault_url= KVUri,credential= credential,connection_verify=False)
    # client_cert = client.get_certificate_version(certificate_name=cert_name, version="x509-cert")
    cert_byte = base64.b64decode(client_cert.value)
    # cert_path='https://key-edge-dev-infra-001.vault.azure.net/certificates/edisoninterca/ce7259c10b21494eb3e6afb6151e08ba/'
    
    # with open(cert_path,'rb') as fopen:
    #     pem_cert_bytes = fopen.read()
        
    with open(cert_pfx,'wb') as fopen:
        fopen.write(cert_byte)
except Exception as ex:
    print(ex)
