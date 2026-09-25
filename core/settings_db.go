package core

import (
	"errors"
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
	return tx.Commit().Error
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
	return SettingsToDB(db, missing)
}
