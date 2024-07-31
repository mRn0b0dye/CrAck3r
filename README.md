# ***CrAck3r***
## About
**Python-based tool for cracking hash**
## Installation
To install ```CrAck3r```, follow these steps:
```
git clone https://github.com/mRn0b0dye/CrAck3r
cd CrAck3r
pip install -r requirements.txt
chmod +x CrAck3r.py 
```
## Features

### Suported Hashing Algorithm 
* SHA1    
* SHA256  
* SHA384  
* SHA512  
* SHA224  
* SHA3_256
* SHA3_384
* SHA3_512
* SHA3_224
* BLAKE2b 
* BLAKE2bs
* MD5

### Easy to use with clear instructions
```
python CrAck3r.py -h
```
<img width="538" alt="image" src="https://github.com/user-attachments/assets/329834eb-197d-4a7d-a9a6-c482dd0db1ce">

### How to specify the hashing algorithm
<img width="478" alt="image" src="https://github.com/user-attachments/assets/203951a7-84d6-4fd4-b47a-b3ce3e07cc27">

>**Setting the value of `-t or --hash-type` according to this table**

### For example 
#### For a single hash
```
python CrAck3r.py -H d6ca3fd0c3a3b462ff2b83436dda495e -t 400 -w wordlist.txt
```
#### For a file containing hashes
```
python CrAck3r.py -f hashes.txt -t 400 -w wordlist.txt
```
