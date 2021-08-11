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
    "lost" :    {  "num" : 1     , "size" : 6548  },
    "pending" : {  "num" : 1     , "size" : 1  },
    "valid" :   {  "num" : 1     , "size" : 4  }
  },
  "srd" : {
    "srd_complete" : 1,
    "srd_remaining_task" : 0,
    "disk_available_for_srd" : 772,
    "disk_available" : 872,
    "disk_volume" : 1372,
    "sys_disk_available" : 300,
    "srd_detail" : {
      "/disk1" : { "srd" : 1, "srd_avail" : 666, "avail" : 716, "volumn" : 916 },
      "/disk2" : { "srd" : 0, "srd_avail" : 106, "avail" : 156, "volumn" : 456 }
    }
  }
}
```
Description:
1. files: give meaningful file information
    1. lost: lost file information, includes 'num' and 'size'
    1. pending: pending file information, includes 'num' and 'size'
    1. valid: valid file information, includes 'num' and 'size'
1. srd: give srd information
    1. srd_complete: srded space volume
    1. srd_remaining_task: remaining srd task
    1. disk_available_for_srd: available volume for srd in current disk
    1. disk_available: free space in current disk
    1. disk_volume: current disk total volume
    1. sys_disk_available: free space of system disk
    1. srd_detail: show disks' detail information

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
  "sworker_version" : "1.0.0",
  "version" : "1.0.0"
}
```

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

Use '/api/v0/file/info_by_type' to get sealed file information by type
----------------------------------------------------------------------
```
curl -XGET http://<url:port>/api/v0/file/info_by_type?type=xxx
```

Parameter:
1. type: file type must be 'all', 'lost', 'pending' and 'valid'

Output:
```json
{
  "lost" : {
    "QmZi65CMEgHQNACjo1b9hbRnjMBjEUadeosLm3wN5pmRU7" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 10 },
  },
  "pending" : {
    "Qmb529vcV8PzhnSigcfGEXd22fyJZMKBKiP1owzNpDtD9H" : { "used_time" : "2s" , "sealed_size" : "24644877" }
  },
  "valid" : {
    "QmRPpSrtgq7dKCMqeqjqnkjKfryMTBosAGRnxzRXTp8euE" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 5 },
    "QmZPWWaP1vrJqWc7c2MCDMQENWjz4a2WvRJpRm1FigNvdt" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 5 },
    "QmZi65CMEgHQNACjo1b9hbRnjMBjEUadeosLm3wN5pmRU6" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 10 },
    "QmaUW39jT5Ty1vJiCXrjcwL6s9c5PoxzUHwM9ZaxD2qG2m" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 5 },
    "Qmam2MemfT4vxSxfwE8eCTnaoj1x545S1gXdL997egxi6S" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 5 },
    "QmbtuWfJKXrofeekRAG3ihSyCVHPtbMhoc6LeMW8ufpsPn" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 5 },
    "QmduVEX5eJxASEtnfYbFk61Wnybs4LNkPDhAdjNq7sEcsK" : { "size" : 10488250 , "s_size" : 10511210 , "c_block_num" : 10 }
  }
}
```

Use '/api/v0/file/info' to get sealed file information by cid
-------------------------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/file/info?cid=QmfSQ6hNXDT5Wx5agiqkfDHtF4D4p2P3hyb1bmEDnbWp3y
```

Parameter:
1. cid: file content id

Output (200, success):
```
{
  "QmfSQ6hNXDT5Wx5agiqkfDHtF4D4p2P3hyb1bmEDnbWp3y" : {
    "c_block_num" : 110,
    "s_size" : 5255889,
    "size" : 5244129,
    "type" : "valid"
  }
}
```
Description:
1. c_block_num: chain block number when sealing the file
1. s_size: sealed file size
1. size: file real size
1. type: file status

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
  "message" : "Change srd interface is stopped due to upgrading or exiting",  
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

Use '/api/v0/storage/seal_start' to seal file start
---------------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/seal_start
--data-raw '{"cid": xxx}'
```

Output (200, success):
```
{
  "message" : "Ready for sealing file 'xxx', waiting for file block",  
  "status_code" : 0
}
```

Output (200, success):
```
{
  "message" : "Same file 'xxx' is being sealed.",  
  "status_code" : 8013
}
```

Output (200, success):
```
{
  "message" : "This file 'xxx' has been sealed",  
  "status_code" : 8012
}
```

Output (400, failed):
```
{
  "message" : "Invalid cid!",  
  "status_code" : 11001
}
```

Output (400, failed):
```
{
  "message" : "Same file 'xxx' is being deleted.",  
  "status_code" : 8014
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! No more file can be sealed! File number reachs the upper limit",  
  "status_code" : 4020
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Unexpected error, error code:xxx",  
  "status_code" : xxx
}
```

Output (500, failed):
```
{
  "message" : "Start seal file '%s' failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : 0
}
```

Output (503, failed):
```
{
  "message" : "Seal file 'xxx' stopped due to upgrading or exiting",  
  "status_code" : 10010
}
```

Use '/api/v0/storage/seal' to seal file
---------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/seal
```

Output (200, success):
```
{
  "message" : "Seal file 'xxx' successfully",  
  "status_code" : 0
}
```

Output (400, failed):
```
{
  "message" : "Invalid cid!",  
  "status_code" : 11001
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Internal error: seal data failed",  
  "status_code" : 4001
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Unexpected error, error code:xxx",  
  "status_code" : xxx
}
```

Output (500, failed):
```
{
  "message" : "Seal file '%s' failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : xxx
}
```

Use '/api/v0/storage/seal_end' to seal file end
-----------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/seal_end
--data-raw '{"cid": xxx}'
```

Output (200, success):
```
{
  "message" : "Seal file 'xxx' successfully",  
  "status_code" : 0
}
```

Output (400, failed):
```
{
  "message" : "Invalid cid!",  
  "status_code" : 11001
}
```

Output (500, failed):
```
{
  "message" : "Seal file 'xxx' failed! Unexpected error, error code:xxx",  
  "status_code" : xxx
}
```

Output (500, failed):
```
{
  "message" : "Start seal file '%s' failed! Invoke SGX API failed! Error code:xxx",  
  "status_code" : xxx
}
```

Output (503, failed):
```
{
  "message" : "Seal file 'xxx' stopped due to upgrading or exiting",  
  "status_code" : 10010
}
```

Use '/api/v0/storage/unseal' to unseal data
-------------------------------------------
```
curl -XPOST http://<url:port>/api/v0/storage/unseal
--data-raw '{"path": "xxx"}'
```

Parameter:
1. path is the index path which indicates data block path

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
