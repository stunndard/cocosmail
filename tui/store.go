package tui

import (
	"errors"
	"os"

	"github.com/stunndard/cocosmail/core"
)

// Store is where the configurator reads and saves settings
type Store interface {
	// Title describes the store, in the window title
	Title() string
	// Load returns values and their source by setting key
	Load() (values, sources map[string]string, err error)
	// Save saves changed settings, by key
	Save(changed map[string]string) error
	// ReadOnly tells why key can't be changed here, "" if it can
	ReadOnly(key string) string
	// ApplyNote tells what happens to changed settings after saving
	ApplyNote(changed []string) string
	// LoadData returns the data: domains, users, aliases...
	LoadData() (*core.Data, error)
	// SaveData saves the changes of data from old (as loaded) to new
	SaveData(old, new *core.Data) error
}

// FileStore edits a config file, it doesn't need a database
type FileStore struct {
	Path string
}

// Title of the store
func (s *FileStore) Title() string {
	return "file " + s.Path
}

// Load reads settings of the file, defaults for the missing ones
func (s *FileStore) Load() (values, sources map[string]string, err error) {
	values = core.SettingsDefaults()
	sources = make(map[string]string, len(values))
	for k := range values {
		sources[k] = core.SourceDefault
	}
	if _, err := os.Stat(s.Path); err != nil {
		return values, sources, nil
	}
	fileValues, _, err := core.ReadSettingsFile(s.Path)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range fileValues {
		values[k], sources[k] = v, core.SourceFile
	}
	return values, sources, nil
}

// Save writes changed settings in the file, keeping its comments.
// A new file gets all settings with their description.
func (s *FileStore) Save(changed map[string]string) error {
	if _, err := os.Stat(s.Path); err != nil {
		values := core.SettingsDefaults()
		for k, v := range changed {
			values[k] = v
		}
		return core.NewConfigFile(values, nil).Write(s.Path)
	}
	f, _, err := core.ReadConfigFile(s.Path)
	if err != nil {
		return err
	}
	for k, v := range changed {
		f.Set(k, v)
	}
	return f.Write(s.Path)
}

// LoadData reads the data of the file, none if it doesn't exist
func (s *FileStore) LoadData() (*core.Data, error) {
	if _, err := os.Stat(s.Path); err != nil {
		return &core.Data{}, nil
	}
	f, _, err := core.ReadConfigFile(s.Path)
	if err != nil {
		return nil, err
	}
	return f.Data()
}

// SaveData writes the changes of data in the file, keeping its comments
func (s *FileStore) SaveData(old, new *core.Data) error {
	f := core.NewConfigFile(nil, nil)
	if _, err := os.Stat(s.Path); err == nil {
		if f, _, err = core.ReadConfigFile(s.Path); err != nil {
			return err
		}
	}
	base, err := f.Data()
	if err != nil {
		return err
	}
	next := core.MergeEdit(base, old, new)
	if errs := core.NewDataErrors(base, next); len(errs) > 0 {
		return errs[0]
	}
	f.SetData(next)
	return f.Write(s.Path)
}

// ReadOnly: everything can be changed in a file
func (s *FileStore) ReadOnly(key string) string {
	return ""
}

// ApplyNote tells how the file is used
func (s *FileStore) ApplyNote(changed []string) string {
	return "cocosmail --config " + s.Path + " loads it at its next start."
}

// DBStore edits settings in the database, core.OpenDB must be called first
type DBStore struct{}

// Title of the store
func (s *DBStore) Title() string {
	if path := core.SettingsManagedBy(core.DB); path != "" {
		return "database, settings managed by " + path + " (read only)"
	}
	return "database"
}

// Load returns the settings the server runs with
func (s *DBStore) Load() (values, sources map[string]string, err error) {
	return core.EffectiveSettings(core.DB)
}

// Save saves changed settings. If settings are not in the database yet,
// all current ones are saved with the changes.
func (s *DBStore) Save(changed map[string]string) error {
	if path := core.SettingsManagedBy(core.DB); path != "" {
		return errors.New("settings are managed by " + path)
	}
	stored, err := core.SettingsFromDB(core.DB)
	if err != nil {
		return err
	}
	if len(stored) > 0 {
		return core.SettingsToDB(core.DB, changed)
	}
	values, _, err := core.EffectiveSettings(core.DB)
	if err != nil {
		return err
	}
	for k, v := range changed {
		values[k] = v
	}
	toImport := make(map[string]string)
	for _, st := range core.Settings {
		if !st.Bootstrap {
			toImport[st.Key] = values[st.Key]
		}
	}
	_, err = core.ImportSettings(core.DB, toImport, false)
	return err
}

// LoadData returns the data in the database
func (s *DBStore) LoadData() (*core.Data, error) {
	return core.ExportData(core.DB)
}

// SaveData saves the changes of data in the database. Data can be changed
// even when settings are managed by a config file: it's imported only into
// an empty database.
func (s *DBStore) SaveData(old, new *core.Data) error {
	_, err := core.EditData(core.DB, old, new)
	return err
}

// ReadOnly tells why a setting can't be changed in the database
func (s *DBStore) ReadOnly(key string) string {
	if path := core.SettingsManagedBy(core.DB); path != "" {
		return "settings are managed by " + path + ", edit it with: cocosmail config edit --file " + path
	}
	if st, _ := core.SettingByKey(key); st.Bootstrap {
		return "it tells where the database is: set it in conf/cocosmail.yaml or in the environment"
	}
	return ""
}

// ApplyNote tells how a running server applies changed settings
func (s *DBStore) ApplyNote(changed []string) string {
	for _, k := range changed {
		if st, _ := core.SettingByKey(k); st.Restart {
			return "A running cocosmail restarts itself within a few seconds to apply them."
		}
	}
	return "A running cocosmail applies them within a few seconds."
}
