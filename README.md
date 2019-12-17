# crust-tee
Implement the trusted layer based on TEE technology, functionally connect  the consensus layer, and be responsible for the trusted verification of the resource layer.

## Dependent library
- Intel sgx
- Boost
- Cpprest

## Build
- Run 'make' in Miner folder

## Run
- Use './app deamon' or './app' to start main progress
- Use './app status' to get and printf validation status
- Use './app report <block_hash>' to get and printf work report

## API
- Use 'curl http://127.0.0.1:12222/api/v0/status' to get validation status
- Use 'curl http://127.0.0.1:12222/api/v0/report\?block_hash\=XXXXX' to get work report
