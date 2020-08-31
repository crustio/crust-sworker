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
    "valid" : {
      "detail" : [
        {  "hash"        : "7dfe61b0c9a1986048f74250bc212af22b17d679bac0a742217b919183f139dd", "size"        : 2097152,
           "sealed_hash" : "db4336bb1837369091f08e30eafbde581b0460355056be94d68d105018fd115e", "sealed_size" : 2098272  },
        {  "hash"        : "760c18649942e92837b4aac6d5d7f6d526ab3f46fc8443b27ed6cfb83b444fb4", "size"        : 3145728,
           "sealed_hash" : "fda9269d8a6e7000c6de9007f386508bb5df95d467741611a2281ae3fc542013", "sealed_size" : 3147408  }
      ],
      "number" : 2
    }
  },
  "srd" : {
    "detail" : {
      "/opt/crust/crust-sworker/0.5.1/tee_base_path/test1" : {  "assigned" : 57,  "available" : 0, "total" : 457  }
    },
    "disk_reserved" : 50,
    "remaining_task" : 1,
    "root_hash" : "6db58e17cb39ae0e6611b2f6aa2f9f2b315ed293dd6c57afece28e3457f68bb6",
    "space" : 57
  }
}
```
Description:
1. files: Give meaningful files' hash, size and status
1. status: There are three status: unconfirmed, lost and valid
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
  "mrenclave" : "aad180124c8670b397a838f552a9136e7e3e7eba2f1c9c49ba16bf53c015b195",
  "pub_key" : "ad288767765f9402ed9a15ecba7fc56a5e39167f94eefe39c05f5f43862686c0b21328d489d3c7d0c4e19445d49a63c1cedbfad9e027166261ae04eb34868514",
  "version" : "0.5.1",
  "tee_version" : "0.5.1"
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

Use 'api/v0/karst/change_url' to change karst url
-------------------------------------------------
```
curl http://<url:port>/api/v0/karst/change_url \
--header 'Content-Type: application/json' \
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
--data-raw '{"karst_url" : "ws://xxxxxx"}'
```

Output (200, success):
```
Change srd file success, the srd workload will change in next validation loop
```

Output (400, empty backup):
```
empty backup
```

Output (401, invalid backup):
```
invalid backup
```

Output (402, invalid karst url):
```
invalid karst url
```

Output (403, internal error):
```
internal error
```

Use 'api/v0/srd/change' to change SRD capacity 
----------------------------------------------
Parameter 'change' in body represents the amount you want to change, the unit is GB, can be positive or negative. Parameter 'backup' in body is your chian account's backup, this need be same as 'chain_backup' in configuration file.
```
curl --location --request POST 'http://<url:port>/api/v0/srd/change' \
--header 'Content-Type: application/json' \
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
--data-raw '{
	"change": 2
}'
```

Output (200, success):
```
Change srd file success, the srd workload will change in next validation loop
```

Output (400, empty backup):
```
empty backup
```

Output (401, invalid backup):
```
invalid backup
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
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
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
1. backup: Indicates identity
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

Output (401, Invalid backup)
```
Invalid backup
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
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
--data-raw '{
    "path" : "/home/xxxx/xxxx/xxxxx"
}'
```

Parameter:
1. backup: Indicates identity
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

Output (401, unseal failed)
```
Unseal file failed!Error invalid backup 
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
Parameter 'hash' in body represents the new file hash you want to confirm. Parameter 'backup' in body is your chian account's backup, this need be same as 'chain_backup' in configuration file.
```
curl --location --request POST 'http://<url:port>/api/v0/storage/confirm' \
--header 'Content-Type: application/json' \
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
--data-raw '{
	"hash": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}'
```

Output (200, success):
```
Confirming new file task has beening added
```

Output (400, empty backup):
```
empty backup
```

Output (401, invalid backup):
```
invalid backup
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
Parameter 'hash' in body represents the file hash you want to delete. Parameter 'backup' in body is your chian account's backup, this need be same as 'chain_backup' in configuration file.
```
curl --location --request POST 'http://<url:port>/api/v0/storage/delete' \
--header 'Content-Type: application/json' \
--header 'backup: {"address":"5FqazaU79hjpEMiWTWZx81VjsYFst15eBuSBKdQLgQibD7CX","encoded":"0xc81537c9442bd1d3f4985531293d88f6d2a960969a88b1cf8413e7c9ec1d5f4955adf91d2d687d8493b70ef457532d505b9cee7a3d2b726a554242b75fb9bec7d4beab74da4bf65260e1d6f7a6b44af4505bf35aaae4cf95b1059ba0f03f1d63c5b7c3ccbacd6bd80577de71f35d0c4976b6e43fe0e1583530e773dfab3ab46c92ce3fa2168673ba52678407a3ef619b5e14155706d43bd329a5e72d36","encoding":{"content":["pkcs8","sr25519"],"type":"xsalsa20-poly1305","version":"2"},"meta":{"name":"Yang1","tags":[],"whenCreated":1580628430860}}' \
--data-raw '{
	"hash": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}'
```

Output (200, success):
```
Deleting file task has beening added
```

Output (400, empty backup):
```
empty backup
```

Output (401, invalid backup):
```
invalid backup
```

Output (402, invalid hash):
```
Delete file failed!Invalid hash!
```

Output (403, invoke SGX API failed):
```
Delete file failed!Invoke SGX API failed!
```
