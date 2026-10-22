package core

import (
	"errors"
	"os/exec"
	"strings"

	"github.com/jinzhu/gorm"
)

// Alias represents a cocosmail alias
type Alias struct {
	ID         int64
	Alias      string `sql:"unique"`
	DeliverTo  string `sql:"null"`
	Pipe       string `sql:"null"`
	IsDomAlias bool   `sql:"default:false"`
	IsMiniList bool   `sql:"default:false"`
}

// AliasGet returns an alias
func AliasGet(aliasStr string) (alias Alias, err error) {
	err = DB.Where("alias = ?", aliasStr).Find(&alias).Error
	return alias, err
}

// AliasAdd adds an alias, checked like in the configurator and config
// import (see ValidateData). An address alias delivers to any addresses
// (deliverTo, separated by spaces, commas or ;), local or not, and/or to a
// command (pipe); its domain is added as local if cocosmail doesn't handle it
// yet. A domain alias delivers to one local domain.
func AliasAdd(alias, deliverTo, pipe string, isMiniList bool) error {
	a := AliasData{
		Alias:     strings.ToLower(strings.TrimSpace(alias)),
		DeliverTo: strings.FieldsFunc(strings.ToLower(deliverTo), func(r rune) bool { return r == ' ' || r == ',' || r == ';' }),
		Pipe:      strings.TrimSpace(pipe),
		MiniList:  isMiniList,
	}
	exists, err := AliasExists(a.Alias)
	if err != nil {
		return err
	}
	if exists {
		return errors.New(a.Alias + " already exists")
	}
	// the command must exist on this server
	if a.Pipe != "" {
		if _, err := exec.LookPath(strings.Fields(a.Pipe)[0]); err != nil {
			return err
		}
	}
	d := &Data{Aliases: []AliasData{a}}
	if t := strings.Split(a.Alias, "@"); len(t) == 2 && t[1] != "" {
		if _, err := RcpthostGet(t[1]); err == gorm.ErrRecordNotFound {
			d.Domains = append(d.Domains, DomainData{Name: t[1], Local: true})
		} else if err != nil {
			return err
		}
	}
	_, err = ImportData(DB, d, false, false)
	return err
}

// AliasDel is used to delete an alias
func AliasDel(alias string) error {
	a, err := AliasGet(alias)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.New("Alias " + alias + " doesn't exists")
		}
		return errors.New("unable to get alias " + alias + ". " + err.Error())
	}
	tx := DB.Begin()
	if a.IsDomAlias {
		if err = tx.Where("hostname=?", a.Alias).Delete(&RcptHost{}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if err = tx.Where("alias = ?", alias).Delete(&Alias{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

// AliasList return all alias
func AliasList() (aliases []Alias, err error) {
	aliases = []Alias{}
	err = DB.Find(&aliases).Error
	return aliases, err
}

// AliasExists checks if an alias exists
func AliasExists(alias string) (bool, error) {
	err := DB.Where("alias=?", strings.ToLower(alias)).Find(&Alias{}).Error
	if err == nil {
		return true, nil
	}
	if err != gorm.ErrRecordNotFound {
		return false, err
	}
	return false, nil
}
