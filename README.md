# crust-tee
Implement the trusted layer based on TEE technology, functionally connect  the consensus layer, and be responsible for the trusted verification of the resource layer.

## Dependent library
- Intel sgx
- Boost

## Package
Run '**scripts/package.sh**' to package whole project, you will get a **crust-\<version\>.tar** package.

## Install
1. Copy TEE application package to your machine, run '**tar -xvf crust-\<version\>.tar**' to extract package.
1. Cd to the extract folder, run '**scripts/install.sh**' to install TEE application. Related dependencies will be installed on your machine. TEE application will be installed on '**/opt/crust/crust-tee**' directory.

## Start
Crust TEE apllication is installed in /opt/crust/crust-tee.
1. In etc/Config.json file you can configure your TEE application configure.
1. After configuration, run '**scripts/start.sh**' to start TEE application.
1. Run '**scripts/stop.sh**' to stop TEE application.
1. Run '**scripts/status.sh -s,--status**' to get process information.
1. Run '**scripts/status.sh -p,--plot**' to get and printf validation status.
1. Run '**scripts/status.sh -r,--report**' to get work report.

## Crust tee executable file
1. Run '**bin/crust-tee -h**' to show how to use **crust-tee**.
1. Run '**bin/crust-tee \<argument\>**' to run crust-tee in different mode, argument can be daemon/server/status/report.
   1. **daemon** option lets tee run in daemon mode.
   1. **server** option lets tee run in server mode.
   1. **status** option shows tee current status, make sure daemon or server mode has been running.
   1. **report** option shows tee work report, make sure daemon or server mode has been running.
1. Run '**bin/crust-tee -c \<config_file_path\>**' to use customized configure file, if not provided **etc/Config.json** will be used as the default one.

## API
- Use 'curl http://<api_base_url_in_Config.json>/api/v0/status' to get validation status
- Use 'curl http://<api_base_url_in_Config.json>/api/v0/report' to get work report

## License

[GPL v3](LICENSE)
