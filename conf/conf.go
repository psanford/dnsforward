package conf

import (
	"fmt"
	"io/ioutil"

	"github.com/gogo/protobuf/proto"
)

func Load(path string) (*Config, error) {
	text, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf Config
	err = proto.UnmarshalText(string(text), &conf)
	if err != nil {
		return nil, fmt.Errorf("Config parse error: %w", err)
	}

	return &conf, nil
}
