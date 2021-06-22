package config

func core() []string {
	return []string{}
}

// smtpd() should return all active plugins.
// The order is important, plugins will always be called
// in the same sequence by the host.
func smtpd() []string {
	return []string{
	"ban",
	"customhelo",
	}
}

func deliveryd() []string {
	return []string{}
}
