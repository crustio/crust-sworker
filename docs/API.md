# APIs
When you start crust-sworker successfully, you can use following commands to request some information:

Use '/api/v0/workload' to get workload
--------------------------------------
```
curl -XGET http://<url:port>/api/v0/workload
```

Output:
```
{
  "files" : {
    "valid" : {  "num" : 1     , "size" : 16781194  }
  },
  "srd" : {
    "srd_complete" : 10,
    "srd_remaining_task" : 2,
    "disk_available_for_srd" : 228,
    "disk_available" : 278,
    "disk_volume" : 456
  }
}
```
Description:
1. files: give meaningful file information
    1. valid: valid file information, includes 'num' and 'size'
1. srd: give srd information
    1. srd_complete: srded space volume
    1. srd_remaining_task: remaining srd task
    1. disk_available_for_srd: available volume for srd in current disk
    1. disk_available: free space in current disk
    1. disk_volume: current disk total volume

Use '/api/v0/stop' to stop sworker
----------------------------------
```
curl -XGET http://<url:port>/api/v0/stop
```

Output (200, success):
```
{
  "message" : "Stop sworker successfully.",  
  "status_code" : 200
}
```

Output (500, failed):
```
{
  "message" : "Stop enclave failed! Invoke SGX API failed!",  
  "status_code" : 500
}
```

Use '/api/v0/enclave/id_info' to get enclave id information
-----------------------------------------------------------
```
curl -XGET http://<url:port>/api/v0/enclave/id_info
```

Output:
```json
{
  "account" : "5EsgXyVJGnoGQ931Vcbzhcsi64unFhCoc5GhZUJnD8qvzu9j",
  "mrenclave" : "cb8a24a6a971d738c6976269358e24bf2af578462fb92ead2d384b619fff6d4a",
  "pub_key" : "95178acfcb9f1406de8b14a5f81fa141a2934fcfc6fefa58077ff6a823711b0d5f884332b0b2a8699cd6ce901a7add1bef97365e3a73054cf383bb8bd3cc9460",
  "sworker_version" : "0.8.0",
  "version" : "0.8.0"
}
```

Use '/api/v0/file/info_all' to get all sealed file information
--------------------------------------------------------------
```
curl -XGET http://<url:port>/api/v0/file/info_all
```

Output:
```
{
  "Qmcs97Lqy6tqmztp2Q7RtzNnmwWFM4X9gH1VK8baUACuen" : { "size" : 16781194 , "s_size" : 16783146 , "c_block_num" : 0 }
}
```
Description:
1. size: file real size
1. s_size: sealed file size
1. c_block_num: chain block number when sealing the file

Use '/api/v0/debug' to set debug flag
-------------------------------------
```
curl -XPOST http://<url:port>/api/v0/debug
--data-raw '{"debug": xxx}'
```

Parameter:
1. debug: only true or false can be accepted

Output (200, success):
```
{
  "message" : "Set debug flag successfully!",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Wrong request body!",  
  "status_code" : 400
}
```

Use '/api/v0/file/info' to get sealed file information by cid
-------------------------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/file/info
--data-raw '{"cid": "xxx"}'
```

Parameter:
1. cid: file content id

Output (200, success):
```
{
  "c_block_num" : 0,
  "s_size" : 16783146,
  "size" : 16781194,
  "smerkletree" : {
    "cid" : "Qmcs97Lqy6tqmztp2Q7RtzNnmwWFM4X9gH1VK8baUACuen",
    "hash" : "55c54c3ce9b68fb2be3ee0c6ae2594d44b798c22eaaa1b12b4da11668861d0ac",
    "links" : [
      {
        "d_hash" : "28cb72d7a0a77857b7308b7f7a7e666ac113e4fd756a6905f5fa663fa6008618"
      },
      {
        "d_hash" : "449d84a283f669309be9b8def4fbc5d36deb44ebdb43d830b6b362b67b704d00"
      },
      {
        "d_hash" : "8d9d6a648e33bf26bf05ca9ff13a0c7aac61d2b9d48f0ffeed23faee4b3a1e78"
      }
    ]
  }
}
```
Description:
1. c_block_num: chain block number when sealing the file
1. s_size: sealed file size
1. size: file real size
1. smerkletree: sealed file merkle tree structure

Output (400, failed):
```
{
  "message" : "Invalid cid",  
  "status_code" : 400
}
```

Output (404, failed):
```
{
  "message" : "File not found.",  
  "status_code" : 404
}
```

Use '/api/v0/srd/ratio' to change srd ratio
-------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/srd/ratio
--data-raw '{"ratio": xxx}'
```

Output (200, success):
```
{
  "message" : "Set srd ratio successfully!",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Invalid srd ratio field!",  
  "status_code" : 400
}
```

Output (400, failed):
```
{
  "message" : "Srd ratio range should be 0 ~ xxx",  
  "status_code" : 400
}
```

Use '/api/v0/srd/change' to change srd
--------------------------------------
```
curl -XPOST http://<url:port>/api/v0/srd/change
--data-raw '{"change": xxx}'
```

Parameter:
1. change: srd task number

Output (200, success):
```
{
  "message" : "Change task:xxxG has been added, will be executed later.",  
  "status_code" : 200
}
```

Output (200, success):
```
{
  "message" : "Only xxxG srd will be added. Rest srd task exceeds upper limit.",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Invalid change",  
  "status_code" : 400
}
```

Output (400, failed):
```
{
  "message" : "No more srd can be added.",  
  "status_code" : 400
}
```

Output (400, failed):
```
{
  "message" : "No srd space to be deleted.",  
  "status_code" : 400
}
```

Output (500, failed):
```
{
  "message" : "Change srd failed! Invoke SGX api failed!",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Unexpected error has occurred!",  
  "status_code" : 500
}
```

Output (503, failed):
```
{
  "message" : "Only xxxG srd will be added. Rest srd task exceeds upper limit.",  
  "status_code" : 503
}
```

Use '/api/v0/storage/delete' to delete meaningful file
------------------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/delete
--data-raw '{"cid": "xxx"}'
```

Parameter:
1. cid: file content id

Output (200, success):
```
{
  "message" : "Deleting file 'xxx' successfully",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Delete file failed! Invalid cid!",  
  "status_code" : 400
}
```

Output (404, failed):
```
{
  "message" : "File 'xxx' is not existed in sworker",  
  "status_code" : 404
}
```

Output (500, failed):
```
{
  "message" : "Delete file 'xxx' failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Unexpected error: xxx",  
  "status_code" : 500
}
```

Output (503, failed):
```
{
  "message" : "Deleting file 'xxx' stoped due to upgrading or exiting",  
  "status_code" : 503
}
```

Use '/api/v0/storage/seal' to seal file
---------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/seal
--data-raw '{"cid": xxx}'
```

Parameter:
1. cid: file content id

Output (200, success):
```
{
  "message" : "Same file 'xxx' is being sealed.",  
  "status_code" : 200
}
```

Output (200, success):
```
{
  "message" : "Seal file 'xxx' successfully",  
  "status_code" : 200
}
```

Output (200, success):
```
{
  "message" : "This file 'xxx' has been sealed",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Invalid cid!",  
  "status_code" : 400
}
```

Output (400, failed):
```
{
  "message" : "Same file 'xxx' is being deleted.",  
  "status_code" : 400
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Can't get block from ipfs",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Internal error: seal data failed",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! No more file can be sealed! File number reachs the upper limit",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Unexpected error, error code:xxx",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Seal file '%s' failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : 500
}
```

Output (503, failed):
```
{
  "message" : "Seal file 'xxx' stoped due to upgrading or exiting",  
  "status_code" : 503
}
```

Use '/api/v0/storage/unseal' to unseal data
-------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/unseal
```

Output (200, success):
```
{
  "message" : "Unseal data successfully!",  
  "status_code" : 200
}
```

Output (400, failed):
```
{
  "message" : "Unseal data failed",  
  "status_code" : 400
}
```

Output (500, failed):
```
{
  "message" : "Unexpected error",  
  "status_code" : 500
}
```

Output (500, failed):
```
{
  "message" : "Unseal failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : 500
}
```

Output (503, failed):
```
{
  "message" : "Unseal file stoped due to upgrading or exiting",  
  "status_code" : 503
}
```
