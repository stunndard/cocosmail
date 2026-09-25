package core

import (
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"strings"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

// User represents a cocosmail user.
type User struct {
	Id           int64
	Login        string `sql:"unique"`
	Passwd       string `sql:"not null"`
	DovePasswd   string `sql:"null"`                     // SHA512 passwd workaround (glibc on most linux flavor doesn't have bcrypt support)
	Active       string `sql:"type:char(1);default:'Y'"` //rune `sql:"type:char(1);not null;default:'Y'`
	AuthRelay    bool   `sql:"default:false"`            // authorization of relaying
	HaveMailbox  bool   `sql:"default:false"`
	IsCatchall   bool   `sql:"default:false"`
	MailboxQuota string `sql:"null"`
	// Home is the mailbox directory, relative to COCOSMAIL_USERS_HOME_BASE
	// so the install can be moved. It's absolute with dovecot LDA, because
	// dovecot reads it from the DB. Use HomePath() to get the full path.
	Home string `sql:"null"`
}

// HomePath returns the absolute path of the user's mailbox directory
func (u *User) HomePath() string {
	if filepath.IsAbs(u.Home) {
		return u.Home
	}
	return filepath.Join(Cfg.GetUsersHomeBase(), u.Home)
}

// userHome returns the home to store in DB for login user@domain
func userHome(user, domain string) string {
	// home = d/domain/u/user
	home := filepath.Join(string(domain[0]), domain, string(user[0]), user)
	if Cfg.GetDovecotSupportEnabled() {
		return filepath.Join(Cfg.GetUsersHomeBase(), home)
	}
	return home
}

// RelativizeUserHomes makes homes under COCOSMAIL_USERS_HOME_BASE relative to it,
// for users created before homes were relative. Not with dovecot LDA.
func RelativizeUserHomes() error {
	if Cfg.GetDovecotSupportEnabled() {
		return nil
	}
	base := Cfg.GetUsersHomeBase() + string(filepath.Separator)
	var users []User
	if err := DB.Where("home LIKE ?", base+"%").Find(&users).Error; err != nil {
		return err
	}
	for _, u := range users {
		if err := DB.Model(&u).Update("home", strings.TrimPrefix(u.Home, base)).Error; err != nil {
			return err
		}
	}
	return nil
}

// UserAdd add an user
func UserAdd(login, passwd, mbQuota string, haveMailbox, authRelay, isCatchall bool) error {
	login = strings.ToLower(login)
	// login must be < 257 char
	l := len(login)
	if l > 256 {
		return errors.New("login must have less than 256 chars")
	}
	if l < 4 {
		return errors.New("login must be at least 4 char")
	}

	// passwd > 6 char
	if len(passwd) < 6 {
		return errors.New("password must be at least 6 chars length")
	}

	// no catchall without mailbox
	if isCatchall && !haveMailbox {
		return errors.New("only users with mailbox can be defined as catchall")
	}

	//OK
	user := &User{
		Login:       login,
		AuthRelay:   authRelay,
		HaveMailbox: haveMailbox,
		IsCatchall:  isCatchall,
	}

	// if we have to create mailbox, login must be a valid email address
	if haveMailbox {
		// check if correct lda is set
		if !Cfg.GetDovecotSupportEnabled() && Cfg.GetLdaType() != "maildir" {
			return errors.New(fmt.Sprintf("invalid lda type: %s. use dovecot/other internal lda", Cfg.GetLdaType()))
		}

		if _, err := mail.ParseAddress(login); err != nil {
			return errors.New("'login' must be a valid email address")
		}

		t := strings.Split(login, "@")
		if len(t) != 2 {
			return errors.New("'login' must be a valid email address")
		}

		// Quota
		if mbQuota == "" {
			// get default
			mbQuota = Cfg.GetUserMailboxDefaultQuota()
		}
		user.MailboxQuota = mbQuota

		// rcpthost must be in rcpthost && must be local && not an alias
		rcpthost, err := RcpthostGet(t[1])
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		exists := err == nil
		if !exists {
			err = DB.Save(&RcptHost{
				Hostname: t[1],
				IsLocal:  true,
			}).Error
			if err != nil {
				return err
			}
		} else if !rcpthost.IsLocal {
			return errors.New("rcpthost " + t[1] + " is already handled by cocosmail but declared as remote destination")
		} else if rcpthost.IsAlias {
			return errors.New("rcpthost " + t[1] + " is an domain alias. You can't add user for this kind of domain")
		}
		user.Home = userHome(t[0], t[1])

		// catchall
		if isCatchall {
			// is there another catchall for this domain
			u, err := UserGetCatchallForDomain(t[1])
			if err != nil {
				if err != gorm.ErrRecordNotFound {
					return errors.New("unable to check catchall existense for domain " + t[1] + ": " + err.Error())
				}
				u = nil
			}
			if u != nil {
				return errors.New("domain " + t[1] + " already have a catchall: " + u.Login)
			}
			user.IsCatchall = true
		}
	}

	var err error
	if user.Passwd, user.DovePasswd, err = HashPassword(passwd); err != nil {
		return err
	}
	return DB.Save(user).Error
}

// UserGet return an user by is login/passwd
func UserGet(login, passwd string) (user *User, err error) {
	user = &User{}
	// check input
	if len(login) == 0 || len(passwd) == 0 {
		err := errors.New("login or passwd is empty")
		return nil, err
	}

	err = DB.Where("login = ?", login).Find(user).Error
	if err != nil {
		return nil, err
	}
	// Encoding passwd
	//hashed, err := bcrypt.GenerateFromPassword([]byte(passwd), 10)
	//log.Println(string(hashed), err)

	// Check passwd
	err = bcrypt.CompareHashAndPassword([]byte(user.Passwd), []byte(passwd))
	return
}

// UserGetByLogin return an user from his login
func UserGetByLogin(login string) (user *User, err error) {
	user = &User{}
	err = DB.Where("login = ?", strings.ToLower(login)).Find(user).Error
	return
}

// UserGetCatchallForDomain return catchall
func UserGetCatchallForDomain(domain string) (user *User, err error) {
	user = &User{}
	err = DB.Where("login LIKE ? AND is_catchall=?", "%"+strings.ToLower(domain), true).Find(user).Error
	return
}

// UserList return all user
func UserList() (users []User, err error) {
	users = []User{}
	err = DB.Find(&users).Error
	return
}

// UserDel delete an user
func UserDel(login string) error {
	exists, err := UserExists(login)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("User " + login + " doesn't exists")
	}
	// TODO on doit verifier si l'host doit etre supprimé de rcpthost
	return DB.Where("login = ?", login).Delete(&User{}).Error
}

// UserExists checks if an user exists
func UserExists(login string) (bool, error) {
	err := DB.Where("login=?", strings.ToLower(login)).Find(&User{}).Error
	if err == nil {
		return true, nil
	}
	if err != gorm.ErrRecordNotFound {
		return false, err
	}
	return false, nil
}

// UserChangePassword is used to change user password
func UserChangePassword(login, password string) error {
	user, err := UserGetByLogin(login)
	if err != nil {
		return err
	}
	return user.ChangePasswd(password)
}

// ChangePasswd is used to change user password
func (u *User) ChangePasswd(passwd string) error {
	var err error
	if u.Passwd, u.DovePasswd, err = HashPassword(passwd); err != nil {
		return err
	}
	return DB.Save(u).Error
}
