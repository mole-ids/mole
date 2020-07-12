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
package rules

import "errors"

const (
	RuleFolderPathIsNotAbsMsg        = "rules folder is not an absolute path"
	IndexFilePathIsNotAbsMsg         = "rules index file is not an absolute path"
	IndexFilePathIsNotAbsEitherMsg   = "rules index file is not an absolute path either"
	IndexOrRuleFolderPathRequiredMsg = "either rules folder or index file is required"
	WrongMetadataFieldMsg            = "wrong metadata entry %s has no value"
	KeywordsNotMeetMsg               = "metadata keyword %s not found while processing the rule"
	RulesManagerInitFailedMsg        = "while initiating the rules manager got"
	IndexFileUsedMsg                 = "loading rules using index %s file"
	RulesFolderUsedMsg               = "loading rules from directory %s"
	TimeElapsedLoadingRulesMsg       = "loaded %d rules without errors in %fs"
	WhileLodingRulesByIndexMsg       = "while loading rules from the index file got"
	WhileLodingRulesByFolderMsg      = "while loading rules from the directory got"
	CleanUpRuleMsg                   = "while removing comments from loaded rules got"
	ReadRuleFileFailedMsg            = "could not read the yara rule %s, because"
	ReadRulesFolderFailedMsg         = "could not read rules directory, because"
	WhileReadingFileMsg              = "while reading file got"
)

var (
	ErrRuleFolderPathIsNotAbs        = errors.New(RuleFolderPathIsNotAbsMsg)
	ErrIndexFilePathIsNotAbs         = errors.New(IndexFilePathIsNotAbsMsg)
	ErrIndexOrRuleFolderPathRequired = errors.New(IndexOrRuleFolderPathRequiredMsg)
)
