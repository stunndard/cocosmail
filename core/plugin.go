package core

import "github.com/jinzhu/gorm"

// Cocosmail core plugin

// Smtpd plugins
var (
	InitSMTPdPlugins func(session *SMTPServerSession)
	ExecSMTPdPlugins func(hook string, session *SMTPServerSession) (done, drop bool)
	AuthSMTPdPlugins func(user, passwd string, success bool, session *SMTPServerSession)
	NotifySMTPdPlugins func(session *SMTPServerSession) (drop bool)
)

// Deliverd plugins

type Plugin struct {
	Id         int64
	PluginName string `sql:"null"`
	ObjectName string `sql:"null"`
	Data       string `sql:"null"`
}

func PluginSaveObject(plugin, name string, j []byte) error {
	var pp Plugin
	_ = DB.Where("plugin_name = ? AND object_name = ?", plugin, name).First(&pp).Error
	p := &Plugin{
		Id:         pp.Id,
		PluginName: plugin,
		ObjectName: name,
		Data:       string(j),
	}
	return DB.Save(p).Error
}

// PluginLoadObject returns the object saved by a plugin, empty if it's not
// saved yet (e.g. fail2ban's IPs before the first ban)
func PluginLoadObject(plugin, name string) ([]byte, error) {
	var p Plugin
	err := DB.Where("plugin_name = ? AND object_name = ?", plugin, name).Find(&p).Error
	if err == gorm.ErrRecordNotFound {
		return []byte{}, nil
	}
	if err != nil {
		return []byte{}, err
	}
	return []byte(p.Data), nil
}
