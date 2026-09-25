package core

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

// DbSetting is a setting stored in the settings table
type DbSetting struct {
	Key       string `gorm:"primary_key;size:64"`
	Value     string `sql:"type:text"`
	UpdatedAt time.Time
}

// TableName of DbSetting
func (DbSetting) TableName() string {
	return "settings"
}

// SettingsFromDB returns settings stored in DB by key.
// Empty if settings are not stored in DB.
func SettingsFromDB(db *gorm.DB) (map[string]string, error) {
	values := make(map[string]string)
	if !db.HasTable(&DbSetting{}) {
		return values, nil
	}
	var rows []DbSetting
	if err := db.Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		// not a setting, see managedByKey
		if strings.HasPrefix(r.Key, "_") {
			continue
		}
		// setting removed from cocosmail, keep it in DB but ignore it
		if _, ok := SettingByKey(r.Key); !ok {
			Logger.Warn("unknown setting " + SettingEnvName(r.Key) + " in database, ignored")
			continue
		}
		values[r.Key] = r.Value
	}
	return values, nil
}

// SettingsToDB validates and saves settings in DB, all or none.
// Bootstrap settings can't be stored in DB.
func SettingsToDB(db *gorm.DB, values map[string]string) error {
	for key, value := range values {
		if err := ValidateSetting(key, value); err != nil {
			return err
		}
		if s, _ := SettingByKey(key); s.Bootstrap {
			return errors.New(SettingEnvName(key) + " tells where the database is, it can't be stored in it")
		}
	}
	tx := db.Begin()
	for key, value := range values {
		if err := tx.Save(&DbSetting{Key: key, Value: value}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	// a running server watches the version to apply changes
	if err := tx.Save(&DbSetting{Key: versionKey, Value: strconv.FormatInt(SettingsVersion(tx)+1, 10)}).Error; err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// versionKey is the settings table row counting changes of settings
const versionKey = "_version"

// SettingsVersion returns the number of changes of settings in DB
func SettingsVersion(db *gorm.DB) int64 {
	var row DbSetting
	if db.Where(&DbSetting{Key: versionKey}).First(&row).Error != nil {
		return 0
	}
	v, _ := strconv.ParseInt(row.Value, 10, 64)
	return v
}

// CurrentSettings returns the settings the server runs with: from DB if they
// are stored there, over config file and environment. inDB is false when
// settings are not stored in DB: config file (file mode), environment and defaults.
func CurrentSettings(db *gorm.DB) (values map[string]string, inDB bool, err error) {
	values, _, _, err = ExternalSettings()
	if err != nil {
		return nil, false, err
	}
	stored, err := SettingsFromDB(db)
	if err != nil {
		return nil, false, err
	}
	for k, v := range stored {
		values[k] = v
	}
	return values, len(stored) > 0, nil
}

// SettingsFillMissing adds settings missing in DB, when settings are stored in DB.
// Needed when a new version adds settings. A missing setting gets its current
// value (from environment) if any, otherwise its default: environment values
// must not be lost when only some settings are in DB.
func SettingsFillMissing(db *gorm.DB, current map[string]string) error {
	stored, err := SettingsFromDB(db)
	if err != nil || len(stored) == 0 {
		return err
	}
	missing := make(map[string]string)
	for _, s := range Settings {
		if _, ok := stored[s.Key]; ok || s.Bootstrap {
			continue
		}
		if v, ok := current[s.Key]; ok {
			missing[s.Key] = v
		} else {
			missing[s.Key] = s.Default
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return SettingsToDB(db, missing)
}

// Setting sources, from lowest to highest priority
const (
	SourceDefault = "default"
	SourceEnv     = "env"
	SourceFile    = "file"
	SourceDB      = "db"
)

// EffectiveSettings returns the value and the source of every setting:
// default, overridden by config file (file mode), environment and DB.
func EffectiveSettings(db *gorm.DB) (values, sources map[string]string, err error) {
	values = SettingsDefaults()
	sources = make(map[string]string, len(values))
	for k := range values {
		sources[k] = SourceDefault
	}
	external, externalSources, _, err := ExternalSettings()
	if err != nil {
		return nil, nil, err
	}
	for k, v := range external {
		values[k], sources[k] = v, externalSources[k]
	}
	stored, err := SettingsFromDB(db)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range stored {
		values[k], sources[k] = v, SourceDB
	}
	return values, sources, nil
}

// ValidateSettings checks all values, and returns all errors
func ValidateSettings(values map[string]string) (errs []error) {
	for _, s := range Settings {
		if v, ok := values[s.Key]; ok {
			if err := ValidateSetting(s.Key, v); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return
}

// UpgradeLegacyValues fixes values written for older cocosmail versions,
// it returns what was changed
func UpgradeLegacyValues(values map[string]string) (notes []string) {
	for _, key := range []string{"smtpd_dsns", "pop3d_dsns"} {
		v, ok := values[key]
		if !ok {
			continue
		}
		dsns := strings.Split(v, ";")
		for i, dsn := range dsns {
			f := strings.Split(dsn, ":")
			if len(f) < 5 {
				continue
			}
			// SSL field was true/false, now ssl/nossl
			switch strings.ToLower(f[len(f)-2]) {
			case "true":
				f[len(f)-2] = "ssl"
			case "false":
				f[len(f)-2] = "nossl"
			}
			dsns[i] = strings.Join(f, ":")
		}
		if nv := strings.Join(dsns, ";"); nv != v {
			values[key] = nv
			notes = append(notes, SettingEnvName(key)+": true/false changed to ssl/nossl")
		}
	}
	return
}

// ImportSettings stores values in DB. Bootstrap settings are skipped.
// Settings not in values get their default, unless merge: then they're kept.
// It returns the keys whose value changed.
func ImportSettings(db *gorm.DB, values map[string]string, merge bool) (changed []string, err error) {
	if !db.HasTable(&DbSetting{}) {
		if err = db.CreateTable(&DbSetting{}).Error; err != nil {
			return nil, err
		}
	}
	stored, err := SettingsFromDB(db)
	if err != nil {
		return nil, err
	}
	final := SettingsDefaults()
	if merge {
		for k, v := range stored {
			final[k] = v
		}
	}
	for k, v := range values {
		final[k] = v
	}
	toStore := make(map[string]string)
	for _, s := range Settings {
		if s.Bootstrap {
			continue
		}
		toStore[s.Key] = final[s.Key]
		if s.Required && final[s.Key] == "" {
			return nil, errors.New("setting " + SettingEnvName(s.Key) + " is missing")
		}
		if old, ok := stored[s.Key]; !ok || old != final[s.Key] {
			changed = append(changed, s.Key)
		}
	}
	if errs := ValidateSettings(toStore); len(errs) > 0 {
		return nil, joinErrors(errs)
	}
	return changed, SettingsToDB(db, toStore)
}

// joinErrors returns one error listing errs, one per line
func joinErrors(errs []error) error {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return errors.New(strings.Join(msgs, "\n"))
}
