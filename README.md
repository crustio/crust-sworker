# crust-tee
Implement the trusted layer based on TEE technology, functionally connect  the consensus layer, and be responsible for the trusted verification of the resource layer.

## Dependent library
- Intel sgx
- Boost
- Cpprest

## Package
Run '**scripts/package.sh**' to package whole project, you will get a **crust-\<version\>.tar** package.

## Install
1. Copy TEE application package to your machine, run '**tar -xvf crust-\<version\>.tar**' to extract package.
1. Cd to the extract folder, run '**scripts/install.sh**' to install TEE application. Related dependencies will be installed on your machine. TEE application will be installed on '**/opt/crust**' directory.

## Start
Crust TEE apllication is installed in /opt/crust.
1. In etc/Config.json file you can configure your TEE application configure.
1. After configuration, run '**scripts/start.sh**' to start TEE application.
1. You can run '**scripts/stop.sh**' to stop TEE application.
1. Run '**scripts/status.sh status**' to get and printf validation status
1. Run '**scripts/status.sh report <block_hash>**' to get and printf work report

## API
- Use 'curl http://127.0.0.1:12222/api/v0/status' to get validation status
- Use 'curl http://127.0.0.1:12222/api/v0/report\?block_hash\=XXXXX' to get work report
