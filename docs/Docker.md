# crust sWorker Docker mode

## Building

### For user
- Install SGX driver.
  ```
  sudo ./scripts/install_sgx_driver.sh
  ```

- Pulll crust sworker runner image.
  ```
  sudo docker pull crustio/crust-sworker:0.5.0
  ```

### For developer
- Build docker env.
  If dependencies don't be changed, you don't need to execute this shell to generate new crust-sworker-env docker.
  ```
  sudo ./docker/build_env.sh
  ```

- Build crust sworker docker.
  ```
  sudo ./docker/build.sh
  ```

## Run
  ```
  sudo docker run -it -e ARGS="-c /opt/crust/crust-sworker/0.5.0/etc/Config.json --offline" --device /dev/isgx --name test-container --network host crustio/crust-sworker:0.5.0
  ```
