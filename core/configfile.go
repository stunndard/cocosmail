package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ConfigFile is a flat config file, one COCOSMAIL_KEY=value per line and
// # comments. It can be used as is as a docker env file.
// Comments, order and unknown lines are kept when it's written back.
type ConfigFile struct {
	lines []configLine
}

type configLine struct {
	// text of a comment, blank or unknown line
	text string
	// key of a setting line
	key   string
	value string
}

// misnamedSettings are names found in old example configs, that cocosmail
// never read, and the setting they were meant for
var misnamedSettings = map[string]string{
	"smtp_max_rcpt":               "smtpd_max_rcpt",
	"smtp_max_bad_rcpt":           "smtpd_max_bad_rcpt",
	"deliverd_use_same_host":      "deliverd_remote_use_same_host",
	"deliverd_local_concurrency":  "deliverd_concurrency_local",
	"deliverd_remote_concurrency": "deliverd_concurrency_remote",
}

// NormalizeSettingKey accepts "smtpd_dsns" or "COCOSMAIL_SMTPD_DSNS"
func NormalizeSettingKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.TrimPrefix(key, "cocosmail_")
}

// ParseConfigFile reads a config file. Old style `export COCOSMAIL_KEY="value"`
// lines are accepted too. Warnings are about lines that are not used as is.
func ParseConfigFile(r io.Reader) (f *ConfigFile, warnings []string, err error) {
	f = &ConfigFile{}
	seen := make(map[string]int)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for scanner.Scan() {
		n++
		text := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
			f.lines = append(f.lines, configLine{text: text})
			continue
		}
		line := trimmed
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			// shell statement end: export COCOSMAIL_SMTPD_LAUNCH=true;
			line = strings.TrimSpace(strings.TrimSuffix(line, ";"))
		}
		eq := strings.Index(line, "=")
		if eq == -1 {
			warnings = append(warnings, fmt.Sprintf("line %d: not KEY=value, ignored: %s", n, trimmed))
			f.lines = append(f.lines, configLine{text: text})
			continue
		}
		name, value := strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:])
		if !strings.HasPrefix(strings.ToUpper(name), "COCOSMAIL_") {
			warnings = append(warnings, fmt.Sprintf("line %d: %s is not a cocosmail setting, ignored", n, name))
			f.lines = append(f.lines, configLine{text: text})
			continue
		}
		key := NormalizeSettingKey(name)
		if _, ok := SettingByKey(key); !ok {
			msg := "unknown setting"
			if key == "base_path" {
				msg = "not used anymore, files are relative to the cocosmail binary directory"
			} else if real, ok := misnamedSettings[key]; ok {
				msg = "wrong name, cocosmail never used it. The setting is " + SettingEnvName(real)
			}
			warnings = append(warnings, fmt.Sprintf("line %d: %s: %s, ignored", n, name, msg))
			f.lines = append(f.lines, configLine{text: text})
			continue
		}
		// docker keeps quotes as part of the value, so they're not written back
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if prev, ok := seen[key]; ok {
			warnings = append(warnings, fmt.Sprintf("line %d: %s already set on line %d, last one is used", n, name, prev))
			f.removeKey(key)
		}
		seen[key] = n
		f.lines = append(f.lines, configLine{key: key, value: value})
	}
	return f, warnings, scanner.Err()
}

// ReadConfigFile reads config file at path
func ReadConfigFile(path string) (*ConfigFile, []string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	return ParseConfigFile(file)
}

// NewConfigFile returns a complete config file with all settings,
// grouped by section and described. values not set get their default.
func NewConfigFile(values map[string]string) *ConfigFile {
	f := &ConfigFile{}
	f.comment("cocosmail configuration")
	f.comment("")
	f.comment("One setting per line: COCOSMAIL_KEY=value, without quotes. An empty value")
	f.comment("means the default. Relative paths are relative to the cocosmail binary")
	f.comment("directory. This file can be used as is as a docker env file.")
	f.comment("")
	f.comment("conf/cocosmail.cfg is imported into the database at the first start, then")
	f.comment("use cocosmail config. With --config FILE, FILE is loaded at every start.")
	section := ""
	for _, s := range Settings {
		if s.Section != section {
			section = s.Section
			f.lines = append(f.lines, configLine{})
			f.comment("--- " + section + " ---")
		}
		f.lines = append(f.lines, configLine{})
		f.describe(s)
		v, ok := values[s.Key]
		if !ok {
			v = s.Default
		}
		f.lines = append(f.lines, configLine{key: s.Key, value: v})
	}
	return f
}

// Values returns settings set in file by key
func (f *ConfigFile) Values() map[string]string {
	values := make(map[string]string)
	for _, l := range f.lines {
		if l.key != "" {
			values[l.key] = l.value
		}
	}
	return values
}

// Get returns value of key and whether it's set in file
func (f *ConfigFile) Get(key string) (string, bool) {
	for _, l := range f.lines {
		if l.key == key {
			return l.value, true
		}
	}
	return "", false
}

// Set sets value of key: in place if set, else appended with its description
func (f *ConfigFile) Set(key, value string) {
	for i := range f.lines {
		if f.lines[i].key == key {
			f.lines[i].value = value
			return
		}
	}
	f.lines = append(f.lines, configLine{})
	if s, ok := SettingByKey(key); ok {
		f.describe(*s)
	}
	f.lines = append(f.lines, configLine{key: key, value: value})
}

// Unset removes key from file, so it gets its default
func (f *ConfigFile) Unset(key string) {
	f.removeKey(key)
}

// Bytes returns the file content
func (f *ConfigFile) Bytes() []byte {
	var b bytes.Buffer
	for _, l := range f.lines {
		if l.key != "" {
			b.WriteString(SettingEnvName(l.key) + "=" + l.value + "\n")
		} else {
			b.WriteString(l.text + "\n")
		}
	}
	return b.Bytes()
}

// Write writes the file at path, atomically, readable by owner only
func (f *ConfigFile) Write(path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(f.Bytes()); err == nil {
		err = tmp.Chmod(0600)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (f *ConfigFile) removeKey(key string) {
	lines := f.lines[:0]
	for _, l := range f.lines {
		if l.key != key {
			lines = append(lines, l)
		}
	}
	f.lines = lines
}

func (f *ConfigFile) comment(text string) {
	if text == "" {
		f.lines = append(f.lines, configLine{text: "#"})
		return
	}
	f.lines = append(f.lines, configLine{text: "# " + text})
}

// describe adds comment lines describing setting s
func (f *ConfigFile) describe(s Setting) {
	text := s.Description
	switch {
	case s.Required:
		text += " (required)"
	case s.Default != "":
		text += " (default: " + s.Default + ")"
	}
	for _, line := range wrap(text, 76) {
		f.comment(line)
	}
}

// wrap splits text in lines of at most width characters, on spaces
func wrap(text string, width int) (lines []string) {
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return
}
