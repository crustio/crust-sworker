package main

import (
	"fmt"
    "os"

	cid "github.com/ipfs/go-cid"
	dshp "github.com/ipfs/go-ipfs-ds-help"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Please input cid!")
    }
	c, _ := cid.Decode(os.Args[1])
	dsKey := dshp.MultihashToDsKey(c.Hash())
	mh, err := dshp.DsKeyToMultihash(dsKey)
	if err != nil {
		fmt.Println(err)
	}
    fmt.Println(dsKey.String()[1:])
	if string(c.Hash()) != string(mh) {
		fmt.Println("should have parsed the same multihash")
	}

	c2, err := dshp.DsKeyToCidV1(dsKey, cid.Raw)
	if err != nil || c.Equals(c2) || c2.Type() != cid.Raw || c2.Version() != 1 {
		fmt.Println("should have been converted to CIDv1-raw")
	}
}
