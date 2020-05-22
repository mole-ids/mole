// Copyright 2020 Jaume Martin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package logger

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

var (
	test_dir = ""
)

func initViper(cfg string) {
	test_dir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}

	name := "mole"
	ext := "yml"
	fname := name + "." + ext
	fpath := filepath.Join(test_dir, fname)

	ioutil.WriteFile(fpath, []byte(cfg), 0655)

	viper.Reset()
	viper.SetConfigType("yaml")
	viper.SetConfigName(name)
	viper.AddConfigPath(test_dir)

	err = viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Fatal error config file: %s", err)
	}
}

func TestLogLevel(t *testing.T) {
	defer os.RemoveAll(test_dir)

	testCase := []struct {
		cfg string
		err bool
	}{{
		cfg: `
logger: 
  log_level: info
  log_to: /dev/stdout
`,
		err: false,
	}, {
		cfg: `
logger: 
  log_level: error
  log_to: /dev/stdout
`,
		err: false,
	}, {
		cfg: `
logger: 
  log_level: warning
  log_to: /dev/stdout
`,
		err: false,
	}, {
		cfg: `
logger: 
  log_level: debug
  log_to: /dev/stdout
`,
		err: false,
	}}

	for idx, tc := range testCase {
		initViper(tc.cfg)
		err := New()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found, %s", idx, err.Error())
		}
	}
}

func TestLogOutput(t *testing.T) {
	defer os.RemoveAll(test_dir)

	testCase := []struct {
		cfg string
		err bool
	}{{
		cfg: `
logger: 
  log_level: info
  log_to: /dev/stdout
`,
		err: false,
	}, {
		cfg: `
logger: 
  log_level: info
  log_to: /dev/null
`,
		err: false,
	}}

	for idx, tc := range testCase {
		initViper(tc.cfg)
		err := New()

		if tc.err && err == nil {
			t.Errorf("[%d] Expecting error but none found", idx)
		}

		if !tc.err && err != nil {
			t.Errorf("[%d] Expecting no error but found, %s", idx, err.Error())
		}
	}
}
