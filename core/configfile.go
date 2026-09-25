package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigFile is a cocosmail config file, in YAML: settings, and data (domains,
// users, aliases, relay IPs, routes, DKIM keys). Comments, order and unknown
// keys are kept when it's written back.
// Old style flat files, one COCOSMAIL_KEY=value per line, are read too, but
// not written: Flat is true for them.
type ConfigFile struct {
	doc  *yaml.Node
	Flat bool
}

// settingsKey is the mapping of settings, the other top level keys are data
const settingsKey = "settings"

// dataSections are the data keys of a config file, with their comment
var dataSections = []struct{ key, comment string }{
	{"domains", "Domains cocosmail accepts mail for. local: true, mail is delivered to mailboxes here, " +
		"false: it's relayed to the domain's servers (or routes)."},
	{"users", "Users. password: in clear text, it's hashed when imported, or password_hash and dovecot_hash " +
		"as exported, none: the current one is kept. mailbox: gets mail, its login is its address. relay: can send mail after " +
		"authentication. catchall: gets the mail of unknown addresses of its domain."},
	{"aliases", "Aliases. An address alias (sales@example.com) is delivered to any addresses " +
		"(deliver_to), local or not, and/or to a command (pipe). minilist: the alias becomes the sender, so bounces " +
		"come back to it. A domain alias (example.org) delivers to the same addresses of one local domain."},
	{"relay_ips", "IP addresses allowed to send mail through cocosmail without authentication."},
	{"routes", "Routes for outgoing mail to destination (a domain, * for all) through remote_host, " +
		"instead of the MX servers. Optional: port (25), priority (lower first), local_ips (like " +
		"deliverd_local_ips), only for an authenticated user or a mail_from, login and password " +
		"on remote_host."},
	{"dkim", "DKIM keys, to sign outgoing mail of domain. The DNS TXT record SELECTOR._domainkey.DOMAIN " +
		"must hold the public key: cocosmail config edit shows it."},
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

// unknownSetting tells why key is not a setting
func unknownSetting(key string) string {
	if key == "base_path" {
		return "not used anymore, files are relative to the cocosmail binary directory"
	}
	if removedSettings[key] {
		return "not used anymore, removed"
	}
	if real, ok := misnamedSettings[key]; ok {
		return "wrong name, cocosmail never used it. The setting is " + real
	}
	return "unknown setting"
}

var flatLine = regexp.MustCompile(`(?m)^\s*(export\s+)?COCOSMAIL_[A-Za-z0-9_]*\s*=`)

// ParseConfigFile reads a config file, YAML or old style flat. Warnings are
// about what is not used as is.
func ParseConfigFile(content []byte) (f *ConfigFile, warnings []string, err error) {
	if flatLine.Match(content) {
		values, warnings, err := parseFlatConfig(bytes.NewReader(content))
		if err != nil {
			return nil, nil, err
		}
		f = NewConfigFile(values, nil)
		f.Flat = true
		return f, warnings, nil
	}
	f = &ConfigFile{doc: &yaml.Node{}}
	if err := yaml.Unmarshal(content, f.doc); err != nil {
		return nil, nil, err
	}
	if f.doc.Kind == 0 {
		// empty file
		f.doc = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if f.root().Kind != yaml.MappingNode {
		return nil, nil, errors.New("not a cocosmail config file: settings: and data sections are expected")
	}
	root := f.root()
	settings := f.settings(false)
	if settings != nil && settings.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("line %d: settings must be key: value lines", settings.Line)
	}
	for i := 0; settings != nil && i < len(settings.Content); i += 2 {
		k, v := settings.Content[i], settings.Content[i+1]
		key := NormalizeSettingKey(k.Value)
		if _, ok := SettingByKey(key); !ok {
			warnings = append(warnings, fmt.Sprintf("line %d: %s: %s, ignored", k.Line, k.Value, unknownSetting(key)))
			continue
		}
		if v.Kind != yaml.ScalarNode {
			warnings = append(warnings, fmt.Sprintf("line %d: %s: the value must be on the same line, ignored", k.Line, k.Value))
		}
	}
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Value != settingsKey && !isDataSection(k.Value) {
			warnings = append(warnings, fmt.Sprintf("line %d: %s is not a cocosmail section, ignored", k.Line, k.Value))
		}
	}
	return f, warnings, nil
}

// parseFlatConfig reads an old style config file: COCOSMAIL_KEY=value lines,
// `export COCOSMAIL_KEY="value"` lines too.
func parseFlatConfig(r io.Reader) (values map[string]string, warnings []string, err error) {
	values = make(map[string]string)
	seen := make(map[string]int)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for scanner.Scan() {
		n++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			// shell statement end: export COCOSMAIL_SMTPD_LAUNCH=true;
			line = strings.TrimSpace(strings.TrimSuffix(line, ";"))
		}
		eq := strings.Index(line, "=")
		if eq == -1 {
			warnings = append(warnings, fmt.Sprintf("line %d: not KEY=value, ignored: %s", n, line))
			continue
		}
		name, value := strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:])
		if !strings.HasPrefix(strings.ToUpper(name), "COCOSMAIL_") {
			warnings = append(warnings, fmt.Sprintf("line %d: %s is not a cocosmail setting, ignored", n, name))
			continue
		}
		key := NormalizeSettingKey(name)
		if _, ok := SettingByKey(key); !ok {
			warnings = append(warnings, fmt.Sprintf("line %d: %s: %s, ignored", n, name, unknownSetting(key)))
			continue
		}
		// docker keeps quotes as part of the value, so they're not written back
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if prev, ok := seen[key]; ok {
			warnings = append(warnings, fmt.Sprintf("line %d: %s already set on line %d, last one is used", n, name, prev))
		}
		seen[key] = n
		values[key] = value
	}
	return values, warnings, scanner.Err()
}

// ReadConfigFile reads config file at path
func ReadConfigFile(path string) (*ConfigFile, []string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	f, warnings, err := ParseConfigFile(content)
	if err != nil {
		return nil, nil, errors.New(path + ": " + err.Error())
	}
	return f, warnings, nil
}

// NewConfigFile returns a complete config file with all settings, grouped by
// section and described, and data. values not set get their default.
func NewConfigFile(values map[string]string, data *Data) *ConfigFile {
	root := &yaml.Node{Kind: yaml.MappingNode}
	f := &ConfigFile{doc: &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}}
	f.doc.HeadComment = comment(
		"cocosmail configuration: settings, and data: domains, users, aliases, relay IPs, routes and DKIM keys.",
		"",
		"Settings are key: value. An empty value means the default. Relative paths are relative to the "+
			"cocosmail binary directory. Environment variables override settings: COCOSMAIL_ME for me.",
		"",
		"conf/cocosmail.yaml is imported into the database at the first start, then use cocosmail config edit. "+
			"With --config FILE, the settings of FILE are loaded at every start, its data only into an "+
			"empty database. cocosmail config export writes settings and data in one file, that "+
			"cocosmail config import loads on any server.",
	)
	settings := &yaml.Node{Kind: yaml.MappingNode}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: settingsKey}, settings)
	section := ""
	for _, s := range Settings {
		v, ok := values[s.Key]
		if !ok {
			v = s.Default
		}
		k, n := settingNodes(s.Key, v)
		if s.Section != section {
			section = s.Section
			k.HeadComment = comment("--- "+section+" ---", "") + "\n" + k.HeadComment
		}
		settings.Content = append(settings.Content, k, n)
	}
	if data == nil || data.Empty() {
		f.doc.FootComment = comment(dataExample...)
	} else {
		f.SetData(data)
	}
	return f
}

// dataExample is shown at the end of a config file without data
var dataExample = []string{
	"Data sections, e.g.:",
	"",
	"domains:",
	"  - name: example.com",
	"    local: true",
	"users:",
	"  - login: john@example.com",
	"    password: change-me",
	"    mailbox: true",
	"    relay: true",
	"aliases:",
	"  - alias: sales@example.com",
	"    deliver_to: [john@example.com]",
	"relay_ips: [192.0.2.10]",
	"routes:",
	"  - destination: example.net",
	"    remote_host: smtp.example.net",
	"    port: 587",
	"dkim:",
	"  - domain: example.com",
	"    selector: s1",
	"    private_key: |",
	"      -----BEGIN RSA PRIVATE KEY-----",
	"      ...",
}

// settingNodes returns the key and value nodes of a setting, the key described
func settingNodes(key, value string) (k, v *yaml.Node) {
	k = &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	if s, ok := SettingByKey(key); ok {
		k.HeadComment = describe(*s)
	}
	v = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	switch SettingKind(key) {
	case reflect.Bool:
		if value == "true" || value == "false" {
			v.Tag = "!!bool"
		}
	case reflect.Int, reflect.Uint64:
		if _, err := strconv.ParseInt(value, 10, 64); err == nil {
			v.Tag = "!!int"
		}
	}
	return k, v
}

func (f *ConfigFile) root() *yaml.Node {
	return f.doc.Content[0]
}

// section returns the value node of top level key, nil if there's none
func (f *ConfigFile) section(key string) *yaml.Node {
	root := f.root()
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1]
		}
	}
	return nil
}

// settings returns the settings mapping, created if needed with create
func (f *ConfigFile) settings(create bool) *yaml.Node {
	n := f.section(settingsKey)
	if n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		// "settings:" without any
		n.Kind, n.Tag, n.Value = yaml.MappingNode, "", ""
	}
	if n == nil && create {
		n = &yaml.Node{Kind: yaml.MappingNode}
		root := f.root()
		root.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Value: settingsKey}, n}, root.Content...)
	}
	return n
}

// Values returns settings set in file by key
func (f *ConfigFile) Values() map[string]string {
	values := make(map[string]string)
	settings := f.settings(false)
	if settings == nil || settings.Kind != yaml.MappingNode {
		return values
	}
	for i := 0; i < len(settings.Content); i += 2 {
		k, v := settings.Content[i], settings.Content[i+1]
		key := NormalizeSettingKey(k.Value)
		if _, ok := SettingByKey(key); !ok || v.Kind != yaml.ScalarNode {
			continue
		}
		if v.Tag == "!!null" {
			values[key] = ""
		} else {
			values[key] = v.Value
		}
	}
	return values
}

// Get returns value of key and whether it's set in file
func (f *ConfigFile) Get(key string) (string, bool) {
	v, ok := f.Values()[key]
	return v, ok
}

// Set sets value of key: in place if set, else added with its description,
// in the order of settings
func (f *ConfigFile) Set(key, value string) {
	settings := f.settings(true)
	k, v := settingNodes(key, value)
	for i := 0; i < len(settings.Content); i += 2 {
		if NormalizeSettingKey(settings.Content[i].Value) == key {
			// keeps the comments of the value
			old := settings.Content[i+1]
			v.LineComment, v.FootComment = old.LineComment, old.FootComment
			settings.Content[i+1] = v
			return
		}
	}
	pos := settingIndex(key)
	at := len(settings.Content)
	for i := 0; i < len(settings.Content); i += 2 {
		if settingIndex(NormalizeSettingKey(settings.Content[i].Value)) > pos {
			at = i
			break
		}
	}
	settings.Content = append(settings.Content[:at], append([]*yaml.Node{k, v}, settings.Content[at:]...)...)
}

// settingIndex returns the position of key in Settings, -1 if unknown
func settingIndex(key string) int {
	for i, s := range Settings {
		if s.Key == key {
			return i
		}
	}
	return -1
}

// Unset removes key from file, so it gets its default
func (f *ConfigFile) Unset(key string) {
	settings := f.settings(false)
	if settings == nil {
		return
	}
	for i := 0; i < len(settings.Content); i += 2 {
		if NormalizeSettingKey(settings.Content[i].Value) == key {
			settings.Content = append(settings.Content[:i], settings.Content[i+2:]...)
			return
		}
	}
}

func isDataSection(key string) bool {
	for _, s := range dataSections {
		if s.key == key {
			return true
		}
	}
	return false
}

// HasData returns true if the file has data sections
func (f *ConfigFile) HasData() bool {
	for _, s := range dataSections {
		if f.section(s.key) != nil {
			return true
		}
	}
	return false
}

// Data returns the data sections. Unknown fields are errors: a misspelled
// field would silently lose its value.
func (f *ConfigFile) Data() (*Data, error) {
	sections := &yaml.Node{Kind: yaml.MappingNode}
	root := f.root()
	for i := 0; i < len(root.Content); i += 2 {
		if isDataSection(root.Content[i].Value) {
			sections.Content = append(sections.Content, root.Content[i], root.Content[i+1])
		}
	}
	d := &Data{}
	if len(sections.Content) == 0 {
		return d, nil
	}
	b, err := yaml.Marshal(sections)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(d); err != nil {
		// line numbers are the ones of the data sections only
		return nil, errors.New(strings.Replace(err.Error(), "yaml: ", "data: ", 1))
	}
	return d, nil
}

// SetData replaces the data sections with d, keeping their comments. Empty
// sections are removed.
func (f *ConfigFile) SetData(d *Data) {
	var n yaml.Node
	if err := n.Encode(d); err != nil {
		// only plain types
		panic(err)
	}
	encoded := make(map[string]*yaml.Node)
	for i := 0; i < len(n.Content); i += 2 {
		encoded[n.Content[i].Value] = n.Content[i+1]
	}
	root := f.root()
	for _, s := range dataSections {
		v := encoded[s.key]
		found := false
		for i := 0; i < len(root.Content); i += 2 {
			if root.Content[i].Value != s.key {
				continue
			}
			found = true
			if v == nil {
				root.Content = append(root.Content[:i], root.Content[i+2:]...)
			} else {
				root.Content[i+1] = v
			}
			break
		}
		if !found && v != nil {
			root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: s.key, HeadComment: comment(s.comment)}, v)
		}
	}
	if !d.Empty() {
		f.doc.FootComment = ""
	}
}

// Bytes returns the file content
func (f *ConfigFile) Bytes() []byte {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(f.doc); err != nil {
		// only plain types
		panic(err)
	}
	enc.Close()
	return airComments(b.Bytes())
}

// airComments puts a blank line before comments that follow a value, they
// describe what comes next. The YAML parser doesn't keep blank lines.
func airComments(content []byte) []byte {
	var out bytes.Buffer
	prev := ""
	// indent of a | or > block scalar header, its content is not touched
	block := -1
	for _, line := range strings.Split(strings.TrimRight(string(content), "\n"), "\n") {
		line = strings.TrimRight(line, " ")
		trimmed := strings.TrimLeft(line, " ")
		indent := len(line) - len(trimmed)
		if block >= 0 && (trimmed == "" || indent > block) {
			out.WriteString(line + "\n")
			continue
		}
		block = -1
		p := strings.TrimSpace(prev)
		// not after the key of a mapping or a list: "settings:"
		if strings.HasPrefix(trimmed, "#") && p != "" && !strings.HasPrefix(p, "#") && !strings.HasSuffix(p, ":") {
			out.WriteString("\n")
		}
		if strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, "|-") || strings.HasSuffix(trimmed, ">") || strings.HasSuffix(trimmed, ">-") {
			block = indent
		}
		out.WriteString(line + "\n")
		prev = line
	}
	return out.Bytes()
}

// Write writes the file at path, atomically, readable by owner only
func (f *ConfigFile) Write(path string) error {
	if f.Flat {
		return errors.New(path + " is an old style config file, convert it first: cocosmail config convert " + path + " NEWFILE.yaml")
	}
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

// comment returns lines as a YAML comment, long lines wrapped
func comment(lines ...string) string {
	var out []string
	for _, l := range lines {
		if l == "" {
			out = append(out, "#")
			continue
		}
		if strings.HasPrefix(l, " ") {
			// preformatted
			out = append(out, "# "+l)
			continue
		}
		for _, w := range wrap(l, 76) {
			out = append(out, "# "+w)
		}
	}
	return strings.Join(out, "\n")
}

// describe returns the comment describing setting s
func describe(s Setting) string {
	text := s.Description
	switch {
	case s.Required:
		text += " (required)"
	case s.RequiredWith != "":
		text += " (required when " + s.RequiredWith + " is true)"
	case s.Default != "":
		text += " (default: " + s.Default + ")"
	}
	return comment(text)
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
