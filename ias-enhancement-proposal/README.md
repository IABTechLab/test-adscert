# ias-enhancements-poc
Authenticated Deliveries and Devices POC

This POC will generate cryptographic signatures for your schain blocks in input/input_json/schain.json.
It will then :
Output a compressed version your schain (minus privacy blocks) using Brotli [output/brotli/output.txt]
Output a plaintext JSON (including privacy blocks) [output/json/output.json]
Output verifier pixels (double sell protection) as designated in the input schain, with macros populated, specific fields digitally signed (using the final bidder's private key) and loaded with the final encrypted schains [output/pixels/verifier_pixels.txt]


## Setup
### 1) generate python venv
python3 -m venv ~/adscert_venv

### 2) install python3 library dependencies
cd [root directory of project]
python3 -m pip install -r ./requirements.txt

### 3) activate venv
source ./adscert_venv/bin/activate









## Customization
### 1) [OPTIONAL] modify input/input_json/schain.json and input/input_json/anon_cert.json to your liking.


### 2) [OPTIONAL] modify any partner keys stored within keys/ecdsa/* using ECDSA prime256v1 key pairs as necessary. (please keep key naming conventions consistent or the script will break!)


### 3) [OPTIONAL] modify shared secrets (input/shared_secrets/shared_secrets.json) between supply chain partners/verifiers AND/OR the final bidder and verifiers as necessary.



## Run
### 1) run script
python3 ./SchainGenerator.py 'bid_id_goes_here'



## Verification

### 1) Verify final bidder's digital signing on challenge fields (the items below are rolled into a single command)
VERIFICATION_PIXEL='https://chainverify.com/pixel?challenge=asd3qb93q0df&context=cspo2nqngv&bid_id=bid548138&potential_verifiers=chainverify.com_verifyprotect.com_vericom.com&final_bidder=final_bidder.com&timestamp=1645660375825727000&bidders_signature=MEYCIQCsPGqq71wBi-TpQcV92n33xE9MGE3H49VE6T8MrLQUmAIhAJJKQ9F08ZCBNEoPfhu9jkpogfT3hlncKGj_hy6lhi8O&schain=KTSCab-3v_i-5KNMb6dKsZpk3MNSO6hc6v3scLC7694zZhnFWsYtEq_z45nEmKyigCGxFIRNyyIUc3ESZs8ZzzEt-KrMsRQRYOfa0VQyD3KFF-jaEcneP-MATGBDyraJdHxdTt8_f2neQdaEjV488PUEbFcviZ887VXqrLSBTcxXQM_EmwLz_MuoM8WmqisRgBHOQZUKTrkl1SJkpFryyur3GQCDymRGilt92np1bGUdt-c2Xd2Qk5geRxz_1e2rRfncXksQPYUrpHyFqILFBgN6DGd60RWfwkj_GMneew0Gs63Fa4tQ3p-HCww_ssI_e-3TpPKkhJ2s6OoWKf3RepfbpYWrHNZGKGnfOr9ohF7cMFRyv9HQFy9Gxf-3x2cDOpKyD1OQoIuXQ6pTqrNTMhOoE2Axuo6G9J0hNqND7KFAuIh_gt92ZVRtEofPBvp5B3-wQEctgvVIscVUmEiiWUq2RLd9dqAgYNQtTLwwluCa22s8rl9ks7MKnCopgQh9tO2cHfqlGnakxHu8ix35IoeCl703PS6v6MIGj77uLsjNtesglixFPfi8VX-vfyLzUkbYa6cmJsAl8H2TFmCznvxSDR6nXMy0dO9JB3VT4zWylY0ZxzRcRgUwGoJDJnaL91n8TdewbV6Ej-BebdVkI5sMRJWu7GNmfj1J8Jx6G7JvJyKoQ_l20BUiAzGh9Xt9Dc8-RN5oz1JCutoxrZhlyZgwsXAlVYMK7okxvFijYfazWbBeNZWxgPgtZxtI1KCr6oQf6IO8b1rBdmQPEvcMSCg8clVRfuE5fRgNrFbu88ZvHChfQfCaM3-i9wpO1M1gFx55erOGv14R4P_4pJFLLD9wOUKN_Ujs6Cwr5ENHPNE=' &&\
QUERY_PARAM="$(echo $VERIFICATION_PIXEL | cut -d'?' -f2)" &&\
IFS="&" read -ra queryArray <<< "$QUERY_PARAM" &&\
echo -n "$(echo ${queryArray[5]} | cut -d'=' -f2):$(echo ${queryArray[1]} | cut -d'=' -f2):$(echo ${queryArray[2]} | cut -d'=' -f2):$(echo ${queryArray[0]} | cut -d'=' -f2):$(echo ${queryArray[3]} | cut -d'=' -f2)" > /tmp/token_plaintext.txt &&\
echo -n "$(echo ${queryArray[6]} | cut -c19-120)" | perl -ne 'tr|-_|+/|; print "$1\n" while length>76 and s/(.{0,76})//; print' | openssl enc -base64 -d > /tmp/token_signed.der && \
openssl dgst -sha1 -verify ./input/keys/ecdsa/final_bidder/secp256r1_public_key.pem -signature /tmp/token_signed.der /tmp/token_plaintext.txt

### 2) Verify schain as verification_vendor
python3 ./SchainVerify.py ./output/protobuf/output.payload



## Caveats
This demonstration uses SECP256k1, but only because I couldn't get SECP256r1 working using Python libraries. Please use NIST256p for any final product.