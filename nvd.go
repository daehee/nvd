package nvd

import (
	"os"
	"path"

	"github.com/valyala/fastjson"
)

type Client struct {
	feedDir    string
	parserPool fastjson.ParserPool
}

func NewClient(baseDir string) (cl *Client, err error) {
	if baseDir == "" {
		baseDir = os.Getenv("PWD")
	}
	feedDir := path.Join(baseDir, "feeds")

	// Check if feeds dir exists, if not create it
	if _, err := os.Stat(feedDir); os.IsNotExist(err) {
		if err := os.Mkdir(feedDir, 0700); err != nil {
			return nil, err
		}
	}

	return &Client{
		feedDir: feedDir,
	}, nil
}
