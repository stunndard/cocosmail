package core

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/toorop/go-dkim"
)

func deliverRemote(d *Delivery) {
	var err error
	ChDeliverdConcurrencyRemoteCount <- 1
	defer func() { ChDeliverdConcurrencyRemoteCount <- -1 }()

	// > concurrency remote ?
	if DeliverdConcurrencyRemoteCount >= Cfg.GetDeliverdConcurrencyRemote() {
		d.requeue()
		return
	}

	time.Sleep(100 * time.Nanosecond)
	Logger.Info(fmt.Sprintf("delivery-remote %s: starting new remote delivery %d/%d from %s to %s - Message-Id: %s - Queue-Id: %s", d.ID, DeliverdConcurrencyRemoteCount, Cfg.GetDeliverdConcurrencyRemote(), d.QMsg.MailFrom, d.QMsg.RcptTo, d.QMsg.MessageId, d.QMsg.Uuid))

	// gatling tests
	//Logger.Info(fmt.Sprintf("deliverd-remote %s: done for gatling test", d.ID))
	//d.dieOk()
	//return

	// Get routes
	d.RemoteRoutes = []Route{}

	// plugins
	// if plugin return false return
	/*
	if !execDeliverdPlugins("remoteinit", d) {
		return
	}
	*/

	// Default routes
	if len(d.RemoteRoutes) == 0 {
		d.RemoteRoutes, err = getRoutes(d.QMsg.MailFrom, d.QMsg.Host, d.QMsg.AuthUser)
		if err != nil {
			d.dieTemp("unable to get route to host "+d.QMsg.Host+". "+err.Error(), true)
			return
		}
	}

	// No routes ?? WTF !
	if len(d.RemoteRoutes) == 0 {
		d.dieTemp("no route to host "+d.QMsg.Host, true)
		return
	}

	// Get client
	client, err := newSMTPClient(d, d.RemoteRoutes, Cfg.GetDeliverdRemoteTimeout())
	if err != nil {
		Logger.Error(fmt.Sprintf("deliverd-remote %s - %s", d.ID, err.Error()))
		d.dieTemp("unable to get client", false)
		return
	}
	defer client.close()

	d.RemoteAddr = client.RemoteAddr()
	d.LocalAddr = client.LocalAddr()

	// EHLO
	code, msg, err := client.Hello()
	d.RemoteSMTPresponseCode = code
	if err != nil {
		switch {
		case code > 399 && code < 500:
			d.dieTemp(fmt.Sprintf("deliverd-remote %s - %s - HELO failed %v - remote server reply %d %s ", d.ID, client.RemoteAddr(), err.Error(), code, msg), true)
			return
		case code > 499:
			d.diePerm(fmt.Sprintf("deliverd-remote %s - %s - HELO failed %v - remote server reply %d %s ", d.ID, client.RemoteAddr(), err.Error(), code, msg), true)
			return
		default:
			Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - HELO unexpected code, remote server reply %d %s ", d.ID, client.RemoteAddr(), code, msg))
		}
	}

	// STARTTLS ?
	// 2013-06-22 14:19:30.670252500 delivery 196893: deferral: Sorry_but_i_don't_understand_SMTP_response_:_local_error:_unexpected_message_/
	// 2013-06-18 10:08:29.273083500 delivery 856840: deferral: Sorry_but_i_don't_understand_SMTP_response_:_failed_to_parse_certificate_from_server:_negative_serial_number_/
	// https://code.google.com/p/go/issues/detail?id=3930data
	if ok, _ := client.Extension("STARTTLS"); ok {
		var config tls.Config
		config.InsecureSkipVerify = Cfg.GetDeliverdRemoteTLSSkipVerify()
		//config.ServerName = Cfg.GetMe()
		code, msg, err = client.StartTLS(&config)
		d.RemoteSMTPresponseCode = code
		// Warning debug
		//err := fmt.Errorf("fake tls error")
		if err != nil {
			Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - TLS negociation failed %d - %s - %v .", d.ID, client.conn.RemoteAddr().String(), code, msg, err))
			if Cfg.GetDeliverdRemoteTLSFallback() {
				// fall back to noTLS
				Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - fallback to no TLS.", d.ID, client.conn.RemoteAddr().String()))
				client.close()
				client, err = newSMTPClient(d, d.RemoteRoutes, Cfg.GetDeliverdRemoteTimeout())
				if err != nil {
					Logger.Error(fmt.Sprintf("deliverd-remote %s - fallback to no TLS failed - %s", d.ID, err.Error()))
					d.dieTemp("unable to get client", false)
					return
				}
				defer client.close()
				code, msg, err = client.Hello()
				if err != nil {
					switch {
					case code > 399 && code < 500:
						d.dieTemp(fmt.Sprintf("deliverd-remote %s - %s - HELO failed %v - remote server reply %d %s ", d.ID, client.RemoteAddr(), err.Error(), code, msg), true)
						return
					case code > 499:
						d.diePerm(fmt.Sprintf("deliverd-remote %s - %s - HELO failed %v - remote server reply %d %s ", d.ID, client.RemoteAddr(), err.Error(), code, msg), true)
						return
					default:
						d.dieTemp(fmt.Sprintf("deliverd-remote %s - %s - HELO unexpected code, remote server reply %d %s ", d.ID, client.RemoteAddr(), code, msg), true)
						return
						//Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - HELO unexpected code, remote server reply %d %s ", d.ID, client.RemoteAddr(), code, msg))
					}
				}
			} else {
				d.dieTemp(fmt.Sprintf("deliverd-remote %s - %s - TLS negociation failed %d - %s - %v .", d.ID, client.conn.RemoteAddr().String(), code, msg, err), true)
				return
			}
		} else {
			Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - TLS negociation succeed - %s %s", d.ID, client.RemoteAddr(), client.TLSGetVersion(), client.TLSGetCipherSuite()))
		}
	}

	// SMTP AUTH
	if client.route.SmtpAuthLogin.Valid && client.route.SmtpAuthPasswd.Valid && len(client.route.SmtpAuthLogin.String) != 0 && len(client.route.SmtpAuthLogin.String) != 0 {
		var auth DeliverdAuth
		_, auths := client.Extension("AUTH")
		if strings.Contains(auths, "CRAM-MD5") {
			auth = CRAMMD5Auth(client.route.SmtpAuthLogin.String, client.route.SmtpAuthPasswd.String)
		} else { // PLAIN
			auth = PlainAuth("", client.route.SmtpAuthLogin.String, client.route.SmtpAuthPasswd.String, client.route.RemoteHost)
		}
		if auth != nil {
			_, msg, err := client.Auth(auth)
			if err != nil {
				message := fmt.Sprintf("deliverd-remote %s - %s - AUTH failed - %s - %s", d.ID, client.RemoteAddr(), msg, err)
				Logger.Error(message)
				d.diePerm(message, false)
				return
			}
		}
	}

	// MAIL FROM
	code, msg, err = client.Mail(d.QMsg.MailFrom)
	d.RemoteSMTPresponseCode = code
	if err != nil {
		message := fmt.Sprintf("deliverd-remote %s - %s - MAIL FROM %s failed %s - %s", d.ID, client.RemoteAddr(), d.QMsg.MailFrom, msg, err)
		Logger.Error(message)
		d.handleSMTPError(code, message)
		return
	}

	// RCPT TO
	code, msg, err = client.Rcpt(d.QMsg.RcptTo)
	d.RemoteSMTPresponseCode = code
	if err != nil {
		message := fmt.Sprintf("deliverd-remote %s - %s - RCPT TO %s failed - %s - %s", d.ID, client.RemoteAddr(), d.QMsg.RcptTo, msg, err)
		Logger.Error(message)
		d.handleSMTPError(code, message)
		return
	}

	// DATA
	dataPipe, code, msg, err := client.Data()
	d.RemoteSMTPresponseCode = code
	if err != nil {
		message := fmt.Sprintf("deliverd-remote %s - %s - DATA command failed - %s - %s", d.ID, client.RemoteAddr(), msg, err)
		Logger.Error(message)
		d.handleSMTPError(code, message)
		return
	}

	// add Received headers
	*d.RawData = append([]byte("Received: cocosmail deliverd remote "+d.ID+"; "+Format822Date()+"\r\n"), *d.RawData...)

	// DKIM ?
	if Cfg.GetDeliverdDkimSign() {
		userDomain := strings.SplitN(d.QMsg.MailFrom, "@", 2)
		if len(userDomain) == 2 {
			dkc, err := DkimGetConfig(userDomain[1])
			if err != nil {
				message := "deliverd-remote " + d.ID + " - unable to get DKIM config for domain " + userDomain[1] + " - " + err.Error()
				Logger.Error(message)
				d.dieTemp(message, false)
				return
			}
			if dkc != nil {
				Logger.Debug(fmt.Sprintf("deliverd-remote %s: add dkim sign", d.ID))
				dkimOptions := dkim.NewSigOptions()
				dkimOptions.PrivateKey = []byte(dkc.PrivKey)
				dkimOptions.AddSignatureTimestamp = true
				dkimOptions.Domain = userDomain[1]
				dkimOptions.Selector = dkc.Selector
				dkimOptions.Headers = []string{"from", "subject", "date", "message-id"}
				dkim.Sign(d.RawData, dkimOptions)
				Logger.Debug(fmt.Sprintf("deliverd-remote %s: end dkim sign", d.ID))
			}
		}
	}

	dataBuf := bytes.NewBuffer(*d.RawData)
	_, err = io.Copy(dataPipe, dataBuf)
	if err != nil {
		message := "deliverd-remote " + d.ID + " - " + client.RemoteAddr() + " - unable to copy dataBuf to dataPipe DKIM config for domain " + " - " + err.Error()
		Logger.Error(message)
		d.dieTemp(message, false)
		return
	}

	dataPipe.WriteCloser.Close()
	code, msg, err = dataPipe.s.text.ReadResponse(-1)
	d.RemoteSMTPresponseCode = code
	Logger.Info(fmt.Sprintf("deliverd-remote %s - %s - reply to DATA cmd: %d - %s - %v", d.ID, client.RemoteAddr(), code, msg, err))
	if err != nil {
		message := fmt.Sprintf("deliverd-remote %s - %s - DATA command failed - %s - %s", d.ID, client.RemoteAddr(), msg, err)
		Logger.Error(message)
		d.dieTemp(message, false)
		return
	}

	if code != 250 {
		message := fmt.Sprintf("deliverd-remote %s - %s - DATA command failed - %d - %s", d.ID, client.RemoteAddr(), code, msg)
		Logger.Error(message)
		d.handleSMTPError(code, message)
		return
	}

	// Bye
	client.Quit()
	d.dieOk()
}
