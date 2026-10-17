package s3fake

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestListObjectsV2Delimiter: a delimited listing rolls keys up into common
// prefixes, page by page, and a key sitting right at the prefix level is
// still listed as an object.
func TestListObjectsV2Delimiter(t *testing.T) {
	s := New()
	defer s.Close()
	s.CreateBucket("b", BucketOptions{})
	c := client(t, s)
	for _, k := range []string{"audit/node=a/2026/10/16/x.jsonl", "audit/node=a/2026/10/17/y.jsonl", "audit/node=b/2026/10/16/z.jsonl", "audit/node=c/2026/10/16/w.jsonl", "audit/node=top.jsonl"} {
		put(t, c, "b", k, "1")
	}
	var prefixes, objects []string
	in := &s3.ListObjectsV2Input{Bucket: aws.String("b"), Prefix: aws.String("audit/node="), Delimiter: aws.String("/"), MaxKeys: aws.Int32(2)}
	for page := 0; ; page++ {
		out, err := c.ListObjectsV2(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		for _, cp := range out.CommonPrefixes {
			prefixes = append(prefixes, aws.ToString(cp.Prefix))
		}
		for _, o := range out.Contents {
			objects = append(objects, aws.ToString(o.Key))
		}
		if !aws.ToBool(out.IsTruncated) {
			break
		}
		if page > 5 {
			t.Fatal("pagination does not end")
		}
		in.ContinuationToken = out.NextContinuationToken
	}
	if strings.Join(prefixes, ",") != "audit/node=a/,audit/node=b/,audit/node=c/" || strings.Join(objects, ",") != "audit/node=top.jsonl" {
		t.Fatalf("prefixes = %v objects = %v", prefixes, objects)
	}
}
