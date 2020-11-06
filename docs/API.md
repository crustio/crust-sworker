# APIs
When you start crust-sworker successfully, you can use following commands to request some information:

Use 'api/v0/workload' to get workload information
-------------------------------------------------
```
curl http://<url:port>/api/v0/workload
```

Output:
```json
{
  "files" : {
    "lost" : { "num" : 0, "size" : 0 },
    "unconfirmed" : { "num" : 0, "size" : 0 },
    "valid" : { "num" : 1, "size" : 90000 }
  },
  "srd" : {
    "detail" : {
      "/opt/crust/data/sworker/srd1" : { "assigned" : 10, "available" : 794,  "total" : 937 }
    },
    "disk_reserved" : 50,
    "remaining_task" : 0,
    "space" : 10
  }
}
```
Description:
1. files: Give meaningful files' hash, size and status
1. srd: Give srd information
1. srd_path_x: Indicates your srd path.
1. assigned: Indicates how many space has been used for srd in the path.
1. available: Indicates how many space could be used for srd in the path.
1. total: Indicates total disk volume.
1. disk_reserved: Indicates disk reserved space, default value is 50 which means sWorker will remain 50GB space for your stuff and the other will be used for srd.
1. remaining_task: Indicates remaining srd task.
1. root_hash: Indicates all srd hash
1. space: Space has been taken by srd

Use 'api/v0/enclave/id_info' to get enclave mrenclave and pub_key
---------------------------------------------------------------------
```
curl http://<url:port>/api/v0/enclave/id_info
```

Output:
```json
{
  "account" : "5EsgXyVJGnoGQ931Vcbzhcsi64unFhCoc5GhZUJnD8qvzu9j",
  "mrenclave" : "cb8a24a6a971d738c6976269358e24bf2af578462fb92ead2d384b619fff6d4a",
  "pub_key" : "95178acfcb9f1406de8b14a5f81fa141a2934fcfc6fefa58077ff6a823711b0d5f884332b0b2a8699cd6ce901a7add1bef97365e3a73054cf383bb8bd3cc9460",
  "sworker_version" : "0.6.0",
  "version" : "0.6.0"
}
```

Use 'api/v0/debug' to set debug flag
------------------------------------
```
curl http://<url:port>/api/v0/debug --data-raw '{"debug" : true}'
```

Parameter:
1. debug: true or false, indicates open or close DEBUG mode.

Output (200, success):
```
Set debug flag successfully
```

Output (400, failed):
```
Set debug flag failed
```

Use 'api/v0/srd/change' to change SRD capacity 
----------------------------------------------
Parameter 'change' in body represents the amount you want to change, the unit is GB, can be positive or negative.
```
curl --location --request POST 'http://<url:port>/api/v0/srd/change' \
--header 'Content-Type: application/json' \
--data-raw '{
	"change": 2
}'
```

Output (200, success):
```
Change srd file success, the srd workload will change in next validation loop
```

Output (402, invalid change):
```
invalid change
```

Output (500, service busy, this API does not support concurrency):
```
Change SRD service busy
```

Output (500, sWorker has not been fully launched , this API does not support concurrency):
```
'sWorker has not been fully launched' or 'Get validation status failed'
```

Use 'storage/seal' to start storage related work 
------------------------------------------------
```
curl --location --request POST 'http://<url:port>/api/v0/storage/seal' \
--header 'Content-Type: application/json' \
--data-raw '{
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
}'
```

Parameter:
1. body: Valid merkletree json structure
1. path: Path to the to be sealed file data

Output (200, success)
```
validate successfully, return sealed merkletree json structure:
{
    "body" : <sealed_merkletree_json>,
    "path" : <path_to_sealed_dir>,
    "status" : 200
}
```

Output (400, Invalid request json)
```
Invalid request json 
```

Output (402, Empty body)
```
Empty body
```

Output (403, Seal failed)
```
Seal failed! Invoke ECALL failed
```

Use 'storage/unseal' to unseal file block
-----------------------------------------
```
curl --location --request POST 'http://<url:port>/api/v0/storage/unseal' \
--header 'Content-Type: application/json' \
--data-raw '{
    "path" : "/home/xxxx/xxxx/xxxxx"
}'
```

Parameter:
1. path: Path to the to be unsealed file data

Output (200, success)
```
unseal data successfully!
{
    "body" : <path_to_new_dir>,
    "status" : 200
}
```

Output (400, unseal failed)
```
Unseal file failed!Error invalid request json!
```

Output (402, unseal failed)
```
Unseal file failed!Error empty file directory
```

Output (403, unseal failed)
```
Unseal file failed!Error Invoke ECALL failed
```

Use 'api/v0/storage/confirm' to confirm new file
------------------------------------------------
Parameter 'hash' in body represents the new file hash you want to confirm.
```
curl --location --request POST 'http://<url:port>/api/v0/storage/confirm' \
--header 'Content-Type: application/json' \
--data-raw '{
	"hash": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}'
```

Output (200, success):
```
Confirming new file task has beening added
```

Output (402, invalid hash):
```
Confirm new file failed!Invalid hash!
```

Output (403, invoke SGX API failed):
```
Confirm new file failed!Invoke SGX API failed!
```

Use 'api/v0/storage/delete' to delete file 
------------------------------------------
Parameter 'hash' in body represents the file hash you want to delete.
```
curl --location --request POST 'http://<url:port>/api/v0/storage/delete' \
--header 'Content-Type: application/json' \
--data-raw '{
	"hash": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}'
```

Output (200, success):
```
Deleting file task has beening added
```

Output (402, invalid hash):
```
Delete file failed!Invalid hash!
```

Output (403, invoke SGX API failed):
```
Delete file failed!Invoke SGX API failed!
```
