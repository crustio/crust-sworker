# Crust sWorker &middot; [![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fcrustio%2Fcrust%2Fbadge&style=flat)](https://github.com/crustio/crust-sworker/actions?query=workflow%3ACI) [![GitHub license](https://img.shields.io/github/license/crustio/crust-sworker)](LICENSE)
sWorker(storage worker) is an offchain storage work inspector of Crust MPoW protocol running inside TEE enclave.

<a href='https://web3.foundation/'><img width='220' alt='Funded by web3 foundation' src='docs/img/web3f_grants_badge.png'></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href='https://builders.parity.io/'><img width='260' src='docs/img/sbp_grants_badge.png'></a>

## Prerequisites:
- Hardware requirements: 
  CPU must contain **SGX module**, and make sure the SGX function is turned on in the bios, please click [this page](https://github.com/crustio/crust/wiki/Check-TEE-supportive) to check if your machine supports SGX
  
- Other configurations
  - **Secure Boot** in BIOS needs to be turned off
  - Need use ordinary account, **cannot support root account**

- Ensure that you have one of the following required operating systems:
  * Ubuntu\* 16.04 LTS Desktop 64bits (just for docker mode)
  * Ubuntu\* 16.04 LTS Server 64bits (just for docker mode)
  * Ubuntu\* 18.04 LTS Desktop 64bits 
  * Ubuntu\* 18.04 LTS Server 64bits 

- Install git-lfs:
  ```
  curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
  sudo apt-get install git-lfs
  git lfs install
  ```

- Clone project
  ```
  git clone https://github.com/crustio/crust-sworker.git
  ```

## Build

### Build from docker
Please refer to [Crust sWorker docker mode](docs/Docker.md)

### Build from source code
- Prerequisites:
  ```
  sudo apt-get update
  sudo apt-get install -y wget expect kmod unzip libboost-all-dev libleveldb-dev build-essential linux-headers-`uname -r` libssl-dev curl libprotobuf-dev libcurl4-openssl-dev
  ```
  ***Note: This mode is just for Ubuntu\* 16.04***

- Install crust sworker
  ```
  sudo ./stripts/install.sh
  ```

## How to use

### Configure
In /opt/crust/crust-sworker/etc/Config.json file you can configure your sworker application.
```
{
    "base_path" : "/opt/crust/crust-sworker/1.0.0/sworker_base_path",    # sWorker key information location, must be absolute path
    "base_url" : "http://127.0.0.1:12222/api/v0",                        # your sWorker node api address
    "data_path" : ["/data1"],                                            # If this item is not set, srd and sealing function cannot be applied
    
    "ipfs_url" : "http://0.0.0.0:5001/api/v0",                           # the IPFS node url

    "chain" : {
        "base_url" : "http://127.0.0.1:56666/api/v1",
        "address" : "cTGVGrFB8suPunnTNEYzDaRdQNPC9QeAGeJDHzs9KXWcM7Wkb",  # the address of crust api
        "account_id" : "069686d23c8e0170553dddca0c36a659c6fc39fa0d5148f1ba1cc95ec4d4c414",
        "password" : "123456",
        "backup" : "{\"encoded\":\"G6l6RC1kWmpIPMgMiUNc9psNwdC7ej0AprgcK6MfJOUAgAAAAQAAAAgAAAD+yayzRW06k1rj4mdPq1KciRiXCItbJucJWanamLURB1PfIcOuxol6zZX6jaKjFFCPAjD6eriU1ZioVaji5KW5VLNRo4V6r03kFYp68tAX7EOl1X5O/sMyu/9+2n6/qMuilIF5knw6mgJC5ajCGmEbPIMVnOXytc//dgHN0z2sVhTtnKZxHYvKCk/143UFo0tv8dFh3oTXbZKR908A\",\"encoding\":{\"content\":[\"pkcs8\",\"sr25519\"],\"type\":[\"scrypt\",\"xsalsa20-poly1305\"],\"version\":\"3\"},\"address\":\"cTGVGrFB8suPunnTNEYzDaRdQNPC9QeAGeJDHzs9KXWcM7Wkb\",\"meta\":{\"genesisHash\":\"0x8b404e7ed8789d813982b9cb4c8b664c05b3fbf433309f603af014ec9ce56a8c\",\"isHardware\":false,\"name\":\"yo\",\"tags\":[],\"whenCreated\":1626234897533}}"
    }
}
```

### Run
```
/opt/crust/crust-sworker/1.0.0/bin/crust-sworker -c /opt/crust/crust-sworker/1.0.0/etc/Config.json
```

### Crust sWorker executable file
1. Run '**bin/crust-sworker -h, --help**' to show how to use ***crust-sworker***.
1. Run '**bin/crust-sworker -c, --config \<config_file_path\>**' to use customized configure file, you can get your own configure file by referring ***etc/Config.json***.
1. Run '**bin/crust-sworker -v, --version**', program will output version information. 
1. Run '**bin/crust-sworker --offline**', program will not interact with the chain.
1. Run '**bin/crust-sworker --debug**', program will output debug logs. 

## APIs
Crust sWorker provides plenty of getting and controlling interfaces, please refer to [Crust sWorker APIs](docs/API.md)

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
- PRs that break the external API must be tagged with [`breaksapi`](https://github.com/crustio/crust-sworker/labels/breakapi);
- No PR should be merged until **all reviews' comments** are addressed.

## License
[GPL v3](LICENSE)
