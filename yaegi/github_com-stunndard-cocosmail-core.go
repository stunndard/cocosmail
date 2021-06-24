// Code generated by 'yaegi extract github.com/stunndard/cocosmail/core'. DO NOT EDIT.

package yaegi

import (
	"bytes"
	"github.com/stunndard/cocosmail/core"
	"go/constant"
	"go/token"
	"io"
	"reflect"
)

func init() {
	Symbols["github.com/stunndard/cocosmail/core/core"] = map[string]reflect.Value{
		// function, constant and variable definitions
		"AddRoute":                         reflect.ValueOf(core.AddRoute),
		"AliasAdd":                         reflect.ValueOf(core.AliasAdd),
		"AliasDel":                         reflect.ValueOf(core.AliasDel),
		"AliasExists":                      reflect.ValueOf(core.AliasExists),
		"AliasGet":                         reflect.ValueOf(core.AliasGet),
		"AliasList":                        reflect.ValueOf(core.AliasList),
		"AutoMigrateDB":                    reflect.ValueOf(core.AutoMigrateDB),
		"Bolt":                             reflect.ValueOf(&core.Bolt).Elem(),
		"Bootstrap":                        reflect.ValueOf(core.Bootstrap),
		"CR":                               reflect.ValueOf(constant.MakeFromLiteral("13", token.INT, 0)),
		"CRAMMD5Auth":                      reflect.ValueOf(core.CRAMMD5Auth),
		"Cfg":                              reflect.ValueOf(&core.Cfg).Elem(),
		"ChDeliverdConcurrencyRemoteCount": reflect.ValueOf(&core.ChDeliverdConcurrencyRemoteCount).Elem(),
		"ChSmtpSessionsCount":              reflect.ValueOf(&core.ChSmtpSessionsCount).Elem(),
		"CocosmailVersion":                 reflect.ValueOf(constant.MakeFromLiteral("\"0.2.0\"", token.STRING, 0)),
		"DB":                               reflect.ValueOf(&core.DB).Elem(),
		"DelRoute":                         reflect.ValueOf(core.DelRoute),
		"DeliverdConcurrencyLocalCount":    reflect.ValueOf(&core.DeliverdConcurrencyLocalCount).Elem(),
		"DeliverdConcurrencyRemoteCount":   reflect.ValueOf(&core.DeliverdConcurrencyRemoteCount).Elem(),
		"DkimDisable":                      reflect.ValueOf(core.DkimDisable),
		"DkimEnable":                       reflect.ValueOf(core.DkimEnable),
		"DkimGetConfig":                    reflect.ValueOf(core.DkimGetConfig),
		"ErrBadDsn":                        reflect.ValueOf(core.ErrBadDsn),
		"ErrNonAsciiCharDetected":          reflect.ValueOf(&core.ErrNonAsciiCharDetected).Elem(),
		"Format822Date":                    reflect.ValueOf(core.Format822Date),
		"GetAllRoutes":                     reflect.ValueOf(core.GetAllRoutes),
		"GetBoltFilePath":                  reflect.ValueOf(core.GetBoltFilePath),
		"GetDsnsFromString":                reflect.ValueOf(core.GetDsnsFromString),
		"InitBolt":                         reflect.ValueOf(core.InitBolt),
		"InitConfig":                       reflect.ValueOf(core.InitConfig),
		"InitDB":                           reflect.ValueOf(core.InitDB),
		"IpCanRelay":                       reflect.ValueOf(core.IpCanRelay),
		"IsIPV4":                           reflect.ValueOf(core.IsIPV4),
		"IsInRcptHost":                     reflect.ValueOf(core.IsInRcptHost),
		"IsOkDB":                           reflect.ValueOf(core.IsOkDB),
		"IsStringInSlice":                  reflect.ValueOf(core.IsStringInSlice),
		"IsValidLocalRcpt":                 reflect.ValueOf(core.IsValidLocalRcpt),
		"LF":                               reflect.ValueOf(constant.MakeFromLiteral("10", token.INT, 0)),
		"LaunchDeliverd":                   reflect.ValueOf(core.LaunchDeliverd),
		"Logger":                           reflect.ValueOf(&core.Logger).Elem(),
		"MailboxAdd":                       reflect.ValueOf(core.MailboxAdd),
		"MailboxDel":                       reflect.ValueOf(core.MailboxDel),
		"MailboxExists":                    reflect.ValueOf(core.MailboxExists),
		"MailboxList":                      reflect.ValueOf(core.MailboxList),
		"NewClamav":                        reflect.ValueOf(core.NewClamav),
		"NewDeliveryMaildir":               reflect.ValueOf(core.NewDeliveryMaildir),
		"NewDiskStore":                     reflect.ValueOf(core.NewDiskStore),
		"NewNSQLogger":                     reflect.ValueOf(core.NewNSQLogger),
		"NewSMTPServerSession":             reflect.ValueOf(core.NewSMTPServerSession),
		"NewSmtpd":                         reflect.ValueOf(core.NewSmtpd),
		"NewStore":                         reflect.ValueOf(core.NewStore),
		"NewUUID":                          reflect.ValueOf(core.NewUUID),
		"NsqQueueProducer":                 reflect.ValueOf(&core.NsqQueueProducer).Elem(),
		"PlainAuth":                        reflect.ValueOf(core.PlainAuth),
		"QueueAddMessage":                  reflect.ValueOf(core.QueueAddMessage),
		"QueueCount":                       reflect.ValueOf(core.QueueCount),
		"QueueGetExpiredMessages":          reflect.ValueOf(core.QueueGetExpiredMessages),
		"QueueGetMessageById":              reflect.ValueOf(core.QueueGetMessageById),
		"QueueListMessages":                reflect.ValueOf(core.QueueListMessages),
		"RcpthostAdd":                      reflect.ValueOf(core.RcpthostAdd),
		"RcpthostDel":                      reflect.ValueOf(core.RcpthostDel),
		"RcpthostGet":                      reflect.ValueOf(core.RcpthostGet),
		"RcpthostGetAll":                   reflect.ValueOf(core.RcpthostGetAll),
		"RelayIpAdd":                       reflect.ValueOf(core.RelayIpAdd),
		"RelayIpDel":                       reflect.ValueOf(core.RelayIpDel),
		"RelayIpGetAll":                    reflect.ValueOf(core.RelayIpGetAll),
		"RemoveBrackets":                   reflect.ValueOf(core.RemoveBrackets),
		"RequeueAll":                       reflect.ValueOf(core.RequeueAll),
		"SmtpSessionsCount":                reflect.ValueOf(&core.SmtpSessionsCount).Elem(),
		"Store":                            reflect.ValueOf(&core.Store).Elem(),
		"StripQuotes":                      reflect.ValueOf(core.StripQuotes),
		"Time822":                          reflect.ValueOf(constant.MakeFromLiteral("\"Mon, 02 Jan 2006 15:04:05 -0700\"", token.STRING, 0)),
		"Unix2dos":                         reflect.ValueOf(core.Unix2dos),
		"UserAdd":                          reflect.ValueOf(core.UserAdd),
		"UserChangePassword":               reflect.ValueOf(core.UserChangePassword),
		"UserDel":                          reflect.ValueOf(core.UserDel),
		"UserExists":                       reflect.ValueOf(core.UserExists),
		"UserGet":                          reflect.ValueOf(core.UserGet),
		"UserGetByLogin":                   reflect.ValueOf(core.UserGetByLogin),
		"UserGetCatchallForDomain":         reflect.ValueOf(core.UserGetCatchallForDomain),
		"UserList":                         reflect.ValueOf(core.UserList),
		"PluginSaveObject":                 reflect.ValueOf(core.PluginSaveObject),
		"PluginLoadObject":                 reflect.ValueOf(core.PluginLoadObject),
		"Version":                          reflect.ValueOf(&core.Version).Elem(),

		// type definitions
		"Alias":             reflect.ValueOf((*core.Alias)(nil)),
		"Config":            reflect.ValueOf((*core.Config)(nil)),
		"DeliverdAuth":      reflect.ValueOf((*core.DeliverdAuth)(nil)),
		"Delivery":          reflect.ValueOf((*core.Delivery)(nil)),
		"DeliveryMaildir":   reflect.ValueOf((*core.DeliveryMaildir)(nil)),
		"DkimConfig":        reflect.ValueOf((*core.DkimConfig)(nil)),
		"Dsn":               reflect.ValueOf((*core.Dsn)(nil)),
		"FileFormatter":     reflect.ValueOf((*core.FileFormatter)(nil)),
		"InternalDelivery":  reflect.ValueOf((*core.InternalDelivery)(nil)),
		"Mailbox":           reflect.ValueOf((*core.Mailbox)(nil)),
		"NSQLogger":         reflect.ValueOf((*core.NSQLogger)(nil)),
		"QMessage":          reflect.ValueOf((*core.QMessage)(nil)),
		"RcptHost":          reflect.ValueOf((*core.RcptHost)(nil)),
		"RelayIpOk":         reflect.ValueOf((*core.RelayIpOk)(nil)),
		"Route":             reflect.ValueOf((*core.Route)(nil)),
		"SMTPServerSession": reflect.ValueOf((*core.SMTPServerSession)(nil)),
		"ServerInfo":        reflect.ValueOf((*core.ServerInfo)(nil)),
		"Smtpd":             reflect.ValueOf((*core.Smtpd)(nil)),
		"Storer":            reflect.ValueOf((*core.Storer)(nil)),
		"User":              reflect.ValueOf((*core.User)(nil)),
		"Plugin":            reflect.ValueOf((*core.Plugin)(nil)),

		// interface wrapper definitions
		"_DeliverdAuth":     reflect.ValueOf((*_github_com_stunndard_cocosmail_core_DeliverdAuth)(nil)),
		"_InternalDelivery": reflect.ValueOf((*_github_com_stunndard_cocosmail_core_InternalDelivery)(nil)),
		"_Storer":           reflect.ValueOf((*_github_com_stunndard_cocosmail_core_Storer)(nil)),
	}
}

// _github_com_stunndard_cocosmail_core_DeliverdAuth is an interface wrapper for DeliverdAuth type
type _github_com_stunndard_cocosmail_core_DeliverdAuth struct {
	WNext  func(fromServer []byte, more bool) (toServer []byte, err error)
	WStart func(server *core.ServerInfo) (proto string, toServer []byte, err error)
}

func (W _github_com_stunndard_cocosmail_core_DeliverdAuth) Next(fromServer []byte, more bool) (toServer []byte, err error) {
	return W.WNext(fromServer, more)
}
func (W _github_com_stunndard_cocosmail_core_DeliverdAuth) Start(server *core.ServerInfo) (proto string, toServer []byte, err error) {
	return W.WStart(server)
}

// _github_com_stunndard_cocosmail_core_InternalDelivery is an interface wrapper for InternalDelivery type
type _github_com_stunndard_cocosmail_core_InternalDelivery struct {
	WCheckConfig func() (err error)
	WDeliver     func(id string, deliverTo string, rawMsg *bytes.Buffer) (permFail bool, err error)
	WGetName     func() string
}

func (W _github_com_stunndard_cocosmail_core_InternalDelivery) CheckConfig() (err error) {
	return W.WCheckConfig()
}
func (W _github_com_stunndard_cocosmail_core_InternalDelivery) Deliver(id string, deliverTo string, rawMsg *bytes.Buffer) (permFail bool, err error) {
	return W.WDeliver(id, deliverTo, rawMsg)
}
func (W _github_com_stunndard_cocosmail_core_InternalDelivery) GetName() string { return W.WGetName() }

// _github_com_stunndard_cocosmail_core_Storer is an interface wrapper for Storer type
type _github_com_stunndard_cocosmail_core_Storer struct {
	WDel func(key string) error
	WGet func(key string) (io.Reader, error)
	WPut func(key string, reader io.Reader) error
}

func (W _github_com_stunndard_cocosmail_core_Storer) Del(key string) error { return W.WDel(key) }
func (W _github_com_stunndard_cocosmail_core_Storer) Get(key string) (io.Reader, error) {
	return W.WGet(key)
}
func (W _github_com_stunndard_cocosmail_core_Storer) Put(key string, reader io.Reader) error {
	return W.WPut(key, reader)
}
