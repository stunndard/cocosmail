package core

import (
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
const DefaultConfigFile = "conf/cocosmail.cfg"

// managedByKey is the settings table row telling which config file manages
// settings, in file mode. Keys starting with _ are not settings.
const managedByKey = "_managed_by"

// ReadSettingsFile reads the settings of a config file, fixing values
// written for older versions. Warnings are about what was not used as is.
func ReadSettingsFile(path string) (values map[string]string, warnings []string, err error) {
	f, warnings, err := ReadConfigFile(path)
	if err != nil {
		return nil, nil, err
	}
	values = f.Values()
	warnings = append(warnings, UpgradeLegacyValues(values)...)
	return values, warnings, nil
}

// ExternalSettings returns settings from the config file overridden by
// environment, with their source. In file mode, all settings of the config
// file. In database mode, only bootstrap settings of conf/cocosmail.cfg, if it
// exists: they tell where the database is, so they can't be in it.
func ExternalSettings() (values, sources map[string]string, warnings []string, err error) {
	values = make(map[string]string)
	sources = make(map[string]string)
	path, onlyBootstrap := ConfigFilePath, false
	if path == "" {
		path, onlyBootstrap = AbsPath(DefaultConfigFile), true
		if _, err := os.Stat(path); err != nil {
			path = ""
		}
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
// Database mode: settings stay in DB. If there are none yet, conf/cocosmail.cfg
// is imported once, if it exists.
func applyConfigSource(db *gorm.DB) error {
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
		return db.Save(&DbSetting{Key: managedByKey, Value: abs}).Error
	}

	if managedBy := SettingsManagedBy(db); managedBy != "" {
		Logger.Info("settings were managed by " + managedBy + ", now the database is the source of truth")
		if err := db.Delete(&DbSetting{Key: managedByKey}).Error; err != nil {
			return err
		}
	}
	stored, err := SettingsFromDB(db)
	if err != nil || len(stored) > 0 {
		return err
	}
	path := AbsPath(DefaultConfigFile)
	if _, err := os.Stat(path); err != nil {
		// settings from environment and defaults, like older versions
		return nil
	}
	values, warnings, err := ReadSettingsFile(path)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		Logger.Warn(path + ": " + w)
	}
	// environment overrides the file, like in file mode
	for k, v := range SettingsFromEnv("cocosmail") {
		values[k] = v
	}
	if _, err = ImportSettings(db, withoutBootstrap(values), false); err != nil {
		return err
	}
	Logger.Info("settings imported from " + path + ", from now on the database is the source of truth")
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
