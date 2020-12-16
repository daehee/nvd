package nvd

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
)

func decompressGZ(rc io.ReadCloser) []byte {
	byteArray, _ := ioutil.ReadAll(rc)
	buffer := bytes.NewBuffer(byteArray)
	reader, _ := gzip.NewReader(buffer)
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	return output.Bytes()
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
