Thanks to https://community.intel.com/t5/Mobile-and-Desktop-Processors/How-to-verify-an-Intel-PTT-endorsement-key-certificate/td-p/1603153/page/2 and support of @fblaese, as well as a bit of AI Help I was able to demystify the Intel TPM Endorsement Key Certificate and being able to verify it.

# Hierarchy

## RootCA Static
```
OnDie CA Root Cert Signing
Download: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer (out of the AIA of the subsidary certificate)
Issuer: C=US, ST=CA, L=Santa Clara, O=Intel Corporation, OU=OnDie CA Root Cert Signing, CN=www.intel.com
Subject: C=US, ST=CA, L=Santa Clara, O=Intel Corporation, OU=OnDie CA Root Cert Signing, CN=www.intel.com
```

## Intermediates Static!

### Intermediate 1
```
OnDie CA CSME Intermediate CA
Download: https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_CSME_Intermediate.cer (out of the AIA of the subsidary certificate)
Issuer: C=US, ST=CA, L=Santa Clara, O=Intel Corporation, OU=OnDie CA Root Cert Signing, CN=www.intel.com
Subject: OU=OnDie CA CSME Intermediate CA, CN=www.intel.com
CRL: https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA.crl
```

### Intermediate 2
```
On Die CSME P_MCC 00001881 Issuing CA
Download: https://tsci.intel.com/content/OnDieCA/certs/MCC_00001881_OnDie_CA.cer (out of the AIA of the subsidary certificate)
Issuer: OU=OnDie CA CSME Intermediate CA, CN=www.intel.com
Subject: OU=On Die CSME P_MCC 00001881 Issuing CA, CN=www.intel.com
CRL: https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Product.crl
```

## Intermediate Variable!

Variable chain from TPM - needs to be extracted each time from the TPM. I use the tpm2_nvread tool to do so.
The properties seem to be identical, but the Authorities itself will vary for sure, why it doesn't make sense to note them here

### Intermediate 3
```
Issuer: OU=On Die CSME P_MCC 00001881 Issuing CA, CN=www.intel.com
Subject: CN=CSME MCC ROM CA
CRL: https://tsci.intel.com/content/OnDieCA/crls/MCC_00001881_OnDie_CA.crl
```

### Intermediate 4
```
Issuer: CN=CSME MCC ROM CA
Subject: CN=CSME MCC SVN01 Kernel CA
CRL: https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
CRL Issuer:  DirName:OU = OnDie CA CSME Intermediate CA, CN = www.intel.com
```

### Intermediate 5
``` 
Issuer: CN=CSME MCC SVN01 Kernel CA
Subject: CN=CSME MCC PTT 01SVN
CRL: https://tsci.intel.com/content/OnDieCA/crls/OnDie_CA_CSME_Indirect.crl
CRL Issuer: DirName:OU = OnDie CA CSME Intermediate CA, CN = www.intel.com
```

# Instructions

To get your three Intermediates you need to export them from your TPM:
`tpm2_nvread -C o 0x01c00100 > chain.der`

As the delimiter is "3082", followed by 2 bytes containing the size of the next certificate you can do this now manually or use the python script:
`python dechainer.py chain.der` # make sure having openssl installed

When you now exported your EK certificate:
`tpm2_getekcertificate > intel-ek.der`
which just for the completeness we convert to base64 pem format too.
`openssl x509 -in intel-ek.der -outform PEM -out intel-ek.pem`

You should be able to successfully verify the chain:
`openssl verify -show_chain -trusted intel-root.pem -untrusted intel-int1.pem -untrusted intel-int2.pem -untrusted intel-int3.pem -untrusted intel-int4.pem -untrusted intel-int5.pem intel-ek.pem`
the result should look like this:
```
intel-ek.pem: OK
Chain:
depth=0:  (untrusted)
depth=1: CN=CSME MCC PTT  01SVN (untrusted)
depth=2: CN=CSME MCC SVN01 Kernel CA (untrusted)
depth=3: CN=CSME MCC ROM CA (untrusted)
depth=4: OU=On Die CSME P_MCC 00001881 Issuing CA, CN=www.intel.com (untrusted)
depth=5: OU=OnDie CA CSME Intermediate CA, CN=www.intel.com (untrusted)
depth=6: C=US, ST=CA, L=Santa Clara, O=Intel Corporation, OU=OnDie CA Root Cert Signing, CN=www.intel.com
```
