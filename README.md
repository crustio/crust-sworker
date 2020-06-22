# Crust TEE &middot; [![Build Status](http://cicd.crust.run:7080/buildStatus/icon?job=crust-tee%2Fmaster)](http://cicd.crust.run:7080/job/crust-tee/job/master/) [![GitHub license](https://img.shields.io/github/license/crustio/crust-tee)](LICENSE)
Implement the trusted layer based on TEE technology, functionally connect  the consensus layer, and be responsible for the trusted verification of the resource layer.

<a href='https://web3.foundation/'><img width='320' alt='Funded by web3 foundation' src='docs/img/web3f_grants_badge.png'></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href='https://builders.parity.io/'><img width='360' src='docs/img/sbp_grants_badge.png'></a>

## Preparation work
- Hardware requirements: 

  CPU must contain **SGX module**, and make sure the SGX function is turned on in the bios, please click [this page](https://github.com/crustio/crust/wiki/Check-TEE-supportive) to check if your machine supports SGX

- Operating system requirements:

  Ubuntu 16.04
  
- Other configurations

  - **Secure Boot** in BIOS needs to be turned off
  - Need use ordinary account, **cannot support root account**


## Dependent library and project
- [Intel SGX](https://software.intel.com/en-us/sgx)
- [Crust](https://github.com/crustio/crust)
- [Crust API](https://github.com/crustio/crust-api)

## Development launch
### Install dependent libs
Install gcc, git, openssl, boost, curl, elf, boost beast
```shell
sudo apt install build-essential
sudo apt install git
sudo apt install libboost-all-dev
sudo apt install openssl
sudo apt install libssl-dev
sudo apt install curl
sudo apt install libelf-dev
sudo apt install libleveldb-dev
```

### Package resources
Run '**scripts/package.sh**' to package whole project, you will get a **crust-\<version\>.tar** package.

### Install crust TEE
1. Run '**tar -xvf crust-\<version\>.tar**' to extract package.
1. Cd to the extract folder, run '**scripts/install.sh**' to install TEE application. Related dependencies will be installed on your machine. TEE application will be installed on '**/opt/crust/crust-tee**' directory.

### Configure your crust TEE
In /opt/crust/crust-tee/etc/Config.json file you can configure your TEE application.
```shell
{
    "base_path" : "/opt/crust/crust-tee/tee_base_path",                  # All files will be stored in this directory, must be absolute path
    "empty_capacity" : 4,                                                # empty disk storage in Gb
    
    "api_base_url": "http://127.0.0.1:12222/api/v0",                     # your tee node api address
    "validator_api_base_url": "http://127.0.0.1:12222/api/v0",           # the tee validator address (**if you are genesis node, this url must equal to 'api_base_url'**)
    "karst_url":  "ws://0.0.0.0:17000/api/v0/node/data",                 # the kasrt node url
    "websocket_url" : "wss://0.0.0.0:19002",
    "websocket_thread_num" : 3,

    "chain_api_base_url" : "http://127.0.0.1:56666/api/v1",              # the address of crust api
    "chain_address" : "",                                                # your crust chain identity
    "chain_account_id" : "",
    "chain_password" : "",
    "chain_backup" : "",
    ......
}
```

### Start
Crust TEE apllication is installed in /opt/crust/crust-tee.

#### Lanuch crust TEE
```shell
cd /opt/crust/crust-tee
./bin/crust-tee --offline # if you want to run crust TEE with crust chain, please remove '--offline' flag
```

## Launch crust chain and API
Crust TEE will wait for the chain to run before uploading identity information and performing file verification. So if you want to test whole TEE flow, please lanuch crust chain and API. Please reference to [crust chain readme](https://github.com/crustio/crust) and [crust api readme](https://github.com/crustio/crust-api) .

## Client launch
### Package resources
Run '**scripts/package.sh**' to package whole project, you will get a **crust-\<version\>.tar** package.

### Launch by using crust client
Please follow [crust client](https://github.com/crustio/crust-client) to launch.

## Crust tee executable file
1. Run '**bin/crust-tee --help**' to show how to use **crust-tee**.
1. Run '**bin/crust-tee \<argument\>**' to run crust-tee in different mode, argument can be daemon/server/status/report.
   1. **daemon** option lets tee run in daemon mode.
   1. **status** option shows tee current status, make sure daemon or server mode has been running.
   1. **report** option shows tee work report, make sure daemon or server mode has been running.
1. Run '**bin/crust-tee --config \<config_file_path\>**' to use customized configure file, if not provided **etc/Config.json** will be used as the default one.
1. Run '**bin/crust-tee --offline**', program will not interact with the chain.
1. Run '**bin/crust-tee --debug**', program will output debug logs. 

## API
### Use 'api/v0/status' to get validation status

Curl shell:
```shell
curl http://<url:port>/api/v0/status
```

Output:
```json
{
  "validation_status": "validate_waiting"
}
```

### Use 'api/v0/report' to get work report

Curl shell:
```shell
curl http://<url:port>/api/v0/report
```

Output:
```json
{
  "pub_key":"4089f15f91bdc18c52f5744ae2ec798c6f2b137bfbbda55ce3a4978b02bdfbdb862cb21295df8d9a896998c90b48838922e655674ecf8dcfe5bb0cdcb157a0db",
  "empty_root":"a03a10a416fe3f994c11f3e8740862385fde5af78af8f2997b7cbe0094424a6e",
  "empty_workload":10737418240,
  "meaningful_workload":0
}
```

### Use 'api/v0/srd/change' to change SRD capacity, 

Parameter 'change' in body represents the amount you want to change, the unit is GB, can be positive or negative. Parameter 'backup' in body is your chian account's backup, this need be same as 'chain_backup' in configuration file.

Curl shell:
```shell
curl --location --request POST 'http://<url:port>/api/v0/srd/change' \
--header 'Content-Type: application/json' \
--header 'backup: {\"address\":\"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX\",\"encoded\":\"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36\",\"encoding\":{\"content\":[\"pkcs8\",\"sr25519\"],\"type\":\"xsalsa20-poly1305\",\"version\":\"2\"},\"meta\":{\"name\":\"Yang1\",\"tags\":[],\"whenCreated\":1580628430860}}' \
--data-raw '{
	"change": 2
}'
```

Output (200, success):
```shell
Change srd file success, the srd workload will change in next validation loop
```

Output (400, empty backup):
```shell
empty backup
```

Output (401, invalid backup):
```shell
invalid backup
```

Output (402, invalid change):
```shell
invalid change
```

Output (500, service busy, this API does not support concurrency):
```shell
Change SRD service busy
```

Output (500, TEE has not been fully launched , this API does not support concurrency):
```shell
'TEE has not been fully launched' or 'Get validation status failed'
```


### Use 'storage/seal' to start storage related work, 
This API is a websocket API.
1. Websocket api: wss://<url:port>/api/v0/storage/seal
```
{
    "backup" : {\"address\":\"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX\",\"encoded\":\"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36\",\"encoding\":{\"content\":[\"pkcs8\",\"sr25519\"],\"type\":\"xsalsa20-poly1305\",\"version\":\"2\"},\"meta\":{\"name\":\"Yang1\",\"tags\":[],\"whenCreated\":1580628430860}},
    "body" : {
        "hash":"0d22d8bbeaca1abebeec956e7e79a5f81c4b30c40a6034b190ff406c68c94c17",
        "links_num":2,
        "size": 4,
        "links":
        [
          {
            "hash":"ca8fcf43b852d7d73801c1c13f38e3d8f80e6c53d4556aa4e18aaa6632c0914b",
            "links_num":2,
            "size": 2,
            "links":
            [
              {
                "hash":"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
                "links_num":0,
                "size": 1,
                "links":[]
              },
              {
                "hash":"82ef6f9e48bcbdf232db1d5c5c6e8f390156f5305b35d4b32f75fc92c8126a32",
                "links_num":0,
                "size": 1,
                "links":[]
              }
            ]
          },
          {
            "hash":"e2f3daf19abfb40766b4c507a9b191fe274f343dfff18287c8e1d8552b8aac77",
            "links_num":2,
            "size": 2,
            "links":
            [
              {
                "hash":"4eaa79a233e1a350bb8d1eba62966f0cf78fe5ae91744420f366d4f19ae268b7",
                "links_num":0,
                "size": 1,
                "links":[]
              },
              {
                "hash":"4eaa79a233e1a350bb8d1eba62966f0cf78fe5ae91744420f366d4f19ae268b7",
                "links_num":0,
                "size": 1,
                "links":[]
              }
            ]
          }
        ]
    },
    "path" : "/home/xxxx/xxxx/xxxxx"
}
```
Parameter:
1. backup: Indicates identity
1. body: Valid merkletree json structure
1. path: Path to the to be sealed file data

Output status:
1. 200: validate successfully, return sealed merkletree json structure
```
{
    "body" : <sealed_merkletree_json>,
    "path" : <path_to_sealed_dir>,
    "status" : 200
}
```
1. 400: Invalid request json 
1. 401: nvalid backup
1. 402: Empty body
1. 403: seal failed! Invoke ECALL failed


### Use 'storage/unseal' to unseal file block, 
This API is a websocket API.
1. Websocket api: wss://<url:port>/api/v0/storage/unseal
```
{
    "backup" : {\"address\":\"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX\",\"encoded\":\"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36\",\"encoding\":{\"content\":[\"pkcs8\",\"sr25519\"],\"type\":\"xsalsa20-poly1305\",\"version\":\"2\"},\"meta\":{\"name\":\"Yang1\",\"tags\":[],\"whenCreated\":1580628430860}},
    "path" : "/home/xxxx/xxxx/xxxxx"
}
```
Parameter:
1. backup: Indicates identity
1. path: Path to the to be unsealed file data

Output status:
1. 200: unseal data successfully!
```
{
    "body" : <seal_msg>,
    "path" : <path_to_new_dir>,
    "status" : 200
}
```
1. 400: Unseal file failed!Error invalid request json!
1. 401: Unseal file failed!Error invalid backup 
1. 402: Unseal file failed!Error empty file directory
1. 403: Unseal file failed!Error Invoke ECALL failed


## Contribution

Thank you for considering to help out with the source code! We welcome contributions from anyone on the internet, and are grateful for even the smallest of fixes!

If you'd like to contribute to crust, please **fork, fix, commit and send a pull request for the maintainers to review and merge into the main codebase**.

### Rules

Please make sure your contribution adhere to our coding guideliness:

- **No --force pushes** or modifying the master branch history in any way. If you need to rebase, ensure you do it in your own repo.
- Pull requests need to be based on and opened against the `master branch`.
- A pull-request **must not be merged until CI** has finished successfully.
- Make sure your every `commit` is [signed](https://help.github.com/en/github/authenticating-to-github/about-commit-signature-verification)

### Merge process

Merging pull requests once CI is successful:

- A PR needs to be reviewed and approved by project maintainers;
- PRs that break the external API must be tagged with [`breaksapi`](https://github.com/crustio/crust-tee/labels/breakapi);
- No PR should be merged until **all reviews' comments** are addressed.

## License

[GPL v3](LICENSE)
