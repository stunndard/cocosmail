package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jinzhu/gorm"
)

// ConfigFilePath is the config file given with --config or COCOSMAIL_CONFIG.
// When set, cocosmail runs in file mode: the file (and COCOSMAIL_* environment
// variables, which override it) is loaded into the database at every server
// start, so the file is the source of truth, e.g. in docker.
// When empty, cocosmail runs in database mode: the database is the source of truth.
var ConfigFilePath string

// DefaultConfigFile is imported into the database at the first server start
// in database mode, if the database has no settings yet
const DefaultConfigFile = "conf/cocosmail.yaml"

// LegacyConfigFile is read when there's no DefaultConfigFile
const LegacyConfigFile = "conf/cocosmail.cfg"

// DefaultConfigPath returns the absolute path of the default config file,
// the legacy one if only it exists, "" if there's none
func DefaultConfigPath() string {
	for _, name := range []string{DefaultConfigFile, LegacyConfigFile} {
		if path := AbsPath(name); fileExists(path) {
			return path
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// managedByKey is the settings table row telling which config file manages
// settings, in file mode. Keys starting with _ are not settings.
const managedByKey = "_managed_by"

// ReadSettingsFile reads the settings of a config file, fixing values
// written for older versions. Warnings are about what was not used as is.
func ReadSettingsFile(path string) (values map[string]string, warnings []string, err error) {
	_, values, warnings, err = ReadConfig(path)
	return
}

// ReadConfig reads a config file and its settings, fixing values written for
// older versions. Warnings are about what was not used as is.
func ReadConfig(path string) (f *ConfigFile, values map[string]string, warnings []string, err error) {
	f, warnings, err = ReadConfigFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	values = f.Values()
	warnings = append(warnings, UpgradeLegacyValues(values)...)
	return f, values, warnings, nil
}

// ExternalSettings returns settings from the config file overridden by
// environment, with their source. In file mode, all settings of the config
// file. In database mode, only bootstrap settings of conf/cocosmail.yaml, if it
// exists: they tell where the database is, so they can't be in it.
func ExternalSettings() (values, sources map[string]string, warnings []string, err error) {
	values = make(map[string]string)
	sources = make(map[string]string)
	path, onlyBootstrap := ConfigFilePath, false
	if path == "" {
		path, onlyBootstrap = DefaultConfigPath(), true
	}
	if path != "" {
		fileValues, w, err := ReadSettingsFile(path)
		if err != nil {
			return nil, nil, nil, err
		}
		warnings = w
		for k, v := range fileValues {
			if s, _ := SettingByKey(k); onlyBootstrap && !s.Bootstrap {
				continue
			}
			values[k], sources[k] = v, SourceFile
		}
	}
	for k, v := range SettingsFromEnv("cocosmail") {
		values[k], sources[k] = v, SourceEnv
	}
	return values, sources, warnings, nil
}

// SettingsManagedBy returns the config file that manages settings stored in DB,
// "" if the database is the source of truth
func SettingsManagedBy(db *gorm.DB) string {
	if !db.HasTable(&DbSetting{}) {
		return ""
	}
	var row DbSetting
	if db.Where(&DbSetting{Key: managedByKey}).First(&row).Error != nil {
		return ""
	}
	return row.Value
}

// applyConfigSource runs at server start, before settings are loaded from DB.
// File mode: config file and environment are imported into DB, the file wins.
// Its data is imported only into an empty database: then data lives in DB.
// Database mode: settings and data stay in DB. If there are no settings yet,
// conf/cocosmail.yaml is imported once, if it exists.
func applyConfigSource(db *gorm.DB) error {
	if !IsOkDB(db) {
		// first start: done once the database is created
		return nil
	}
	if ConfigFilePath != "" {
		values, _, warnings, err := ExternalSettings()
		if err != nil {
			return err
		}
		for _, w := range warnings {
			Logger.Warn(ConfigFilePath + ": " + w)
		}
		if _, err = ImportSettings(db, withoutBootstrap(values), false); err != nil {
			return err
		}
		abs, _ := filepath.Abs(ConfigFilePath)
		Logger.Info("settings loaded from " + abs)
		if err = db.Save(&DbSetting{Key: managedByKey, Value: abs}).Error; err != nil {
			return err
		}
		return importFileData(db, abs, true)
	}

	if managedBy := SettingsManagedBy(db); managedBy != "" {
		Logger.Info("settings were managed by " + managedBy + ", now the database is the source of truth")
		if err := db.Delete(&DbSetting{Key: managedByKey}).Error; err != nil {
			return err
		}
	}
	_, err := ImportDefaultConfig(db)
	return err
}

// ImportDefaultConfig imports conf/cocosmail.yaml, settings and data, if the
// database has no settings yet, like at the first start in database mode. It
// returns the file imported, "" if none.
func ImportDefaultConfig(db *gorm.DB) (path string, err error) {
	stored, err := SettingsFromDB(db)
	if err != nil || len(stored) > 0 {
		return "", err
	}
	path = DefaultConfigPath()
	if path == "" {
		// settings from environment and defaults, like older versions
		return "", nil
	}
	values, warnings, err := ReadSettingsFile(path)
	if err != nil {
		return "", err
	}
	for _, w := range warnings {
		Logger.Warn(path + ": " + w)
	}
	// environment overrides the file, like in file mode
	for k, v := range SettingsFromEnv("cocosmail") {
		values[k] = v
	}
	if _, err = ImportSettings(db, withoutBootstrap(values), false); err != nil {
		return "", errors.New(path + ": " + err.Error())
	}
	Logger.Info("settings imported from " + path + ", from now on the database is the source of truth")
	return path, importFileData(db, path, false)
}

// importFileData imports the data of config file path, if the database has
// none. Else, with tell, it tells the file's data is not used.
func importFileData(db *gorm.DB, path string, tell bool) error {
	f, _, err := ReadConfigFile(path)
	if err != nil || !f.HasData() {
		return err
	}
	empty, err := DataEmpty(db)
	if err != nil {
		return err
	}
	if !empty {
		if tell {
			Logger.Info("data of " + path + " not imported, the database has data. To import it: cocosmail config import " + path)
		}
		return nil
	}
	d, err := f.Data()
	if err != nil {
		return errors.New(path + ": " + err.Error())
	}
	// users' homes depend on settings just imported
	if err = loadDBSettings(db); err != nil {
		return err
	}
	changes, err := ImportData(db, d, false, false)
	if err != nil {
		return errors.New(path + ": " + err.Error())
	}
	Logger.Info(fmt.Sprintf("data imported from %s: %d changes", path, len(changes)))
	return nil
}

// withoutBootstrap returns values without bootstrap settings, they can't be in DB
func withoutBootstrap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		if s, ok := SettingByKey(k); ok && !s.Bootstrap {
			out[k] = v
		}
	}
	return out
}
