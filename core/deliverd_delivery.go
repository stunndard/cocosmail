package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bitly/go-nsq"
	"github.com/jinzhu/gorm"
	"github.com/toorop/tmail/message"
	"github.com/toorop/tmail/scope"
	"github.com/toorop/tmail/store"
	"io/ioutil"
	"math/rand"
	"net"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"text/template"
	"time"
)

type delivery struct {
	id      string
	nsqMsg  *nsq.Message
	qMsg    *QMessage
	rawData *[]byte
	qStore  store.Storer
}

// processMsg processes message
// TODO :
// - ajout header recieved
// - ajout header tmail-msg-id
func (d *delivery) processMsg() {
	var err error
	// Recover on panic
	defer func() {
		if err := recover(); err != nil {
			scope.Log.Error(fmt.Sprintf("deliverd-remote %s : PANIC \r\n %s \r\n %s", d.id, err, debug.Stack()))
		}
	}()

	// decode message from json
	if err = json.Unmarshal([]byte(d.nsqMsg.Body), d.qMsg); err != nil {
		scope.Log.Error("deliverd-remote: unable to parse nsq message - " + err.Error())
		// TODO
		// in this case :
		// on expire le message de la queue par contre on ne
		// le supprime pas de la db
		// un process doit venir checker la db regulierement pour voir si il
		// y a des problemes
		return
	}

	scope.Log.Info(fmt.Sprintf("deliverd %s: starting new delivery from %s to %s (msg id: %s)", d.id, d.qMsg.MailFrom, d.qMsg.RcptTo, d.qMsg.Key))

	// Update qMessage from db (check if exist)
	if err = d.qMsg.UpdateFromDb(); err != nil {
		// si on ne le trouve pas en DB il y a de forte chance pour que le message ait déja
		// été traité
		if err == gorm.RecordNotFound {
			scope.Log.Info(fmt.Sprintf("deliverd %s : qMsg %s not in Db, already delivered, discarding", d.id, d.qMsg.Key))
			d.discard()
		} else {
			scope.Log.Error(fmt.Sprintf("deliverd %s : unable to get qMsg %s from Db - %s", d.id, d.qMsg.Key, err))
			d.requeue()
		}
		return
	}

	// Discard ?
	if d.qMsg.Status == 1 {
		d.qMsg.Status = 0
		d.qMsg.SaveInDb()
		d.discard()
		return
	}

	// {"Id":7,"Key":"7f88b72858ae57c17b6f5e89c1579924615d7876","MailFrom":"toorop@toorop.fr",
	// "RcptTo":"toorop@toorop.fr","Host":"toorop.fr","AddedAt":"2014-12-02T09:05:59.342268145+01:00",
	// "DeliveryStartedAt":"2014-12-02T09:05:59.34226818+01:00","NextDeliveryAt":"2014-12-02T09:05:59.342268216+01:00",
	// "DeliveryInProgress":true,"DeliveryFailedCount":0}

	// Retrieve message from store
	// c'est le plus long (enfin ça peut si c'est par exemple sur du S3 ou RA)
	d.qStore, err = store.New(scope.Cfg.GetStoreDriver(), scope.Cfg.GetStoreSource())
	if err != nil {
		// TODO
		// On va considerer que c'est une erreur temporaire
		// il se peut que le store soit momentanément injoignable
		// A terme on peut regarder le
		scope.Log.Error(fmt.Sprintf("deliverd %s : unable to get rawmail %s from store - %s", d.id, d.qMsg.Key, err))
		d.requeue()
		return
		//return response, errors.New("unable to get raw mail from store")
	}
	//d.qStore = qStore
	dataReader, err := d.qStore.Get(d.qMsg.Key)
	if err != nil {
		d.dieTemp("unable to retrieve raw mail from store. " + err.Error())
		return
	}

	// get rawData
	t, err := ioutil.ReadAll(dataReader)
	if err != nil {
		d.dieTemp("unable to read raw mail from dataReader. " + err.Error())
		return
	}
	d.rawData = &t

	// Marked  ?
	if d.qMsg.Status == 3 {
		d.bounce("bounced by admin")
		return
	}

	// update status to delivery in progress
	d.qMsg.Status = 0
	d.qMsg.SaveInDb()

	//
	// Local or  remote ?
	//

	local, err := isLocalDelivery(d.qMsg.RcptTo)
	if err != nil {
		d.dieTemp("unable to check if it's local delivery. " + err.Error())
		return
	}

	if local {
		deliverLocal(d)
	} else {
		deliverRemote(d)
	}

	// REMOTE
	/*
		// Get route
		routes, err := getRoutes(d.qMsg.MailFrom, d.qMsg.Host, d.qMsg.AuthUser)
		scope.Log.Debug("deliverd-remote: ", routes, err)
		if err != nil {
			d.dieTemp("unable to get route to host " + d.qMsg.Host + ". " + err.Error())
			return
		}

		// Get client
		c, r, err := getSmtpClient(routes)
		//scope.Log.Debug(c, r, err)
		if err != nil {
			// TODO
			d.dieTemp("unable to get client")
			return
		}
		defer c.Close()

		// STARTTLS ?
		// 2013-06-22 14:19:30.670252500 delivery 196893: deferral: Sorry_but_i_don't_understand_SMTP_response_:_local_error:_unexpected_message_/
		// 2013-06-18 10:08:29.273083500 delivery 856840: deferral: Sorry_but_i_don't_understand_SMTP_response_:_failed_to_parse_certificate_from_server:_negative_serial_number_/
		// https://code.google.com/p/go/issues/detail?id=3930
		if ok, _ := c.Extension("STARTTLS"); ok {
			var config tls.Config
			config.InsecureSkipVerify = true
			// If TLS nego failed bypass secure transmission
			err = c.StartTLS(&config)
			if err != nil { // fallback to no TLS
				c.Close()
				c, r, err = getSmtpClient(routes)
				if err != nil {
					// TODO
					d.dieTemp("unable to get client")
				}
				defer c.Close()
			}
		}

		// SMTP AUTH
		if r.SmtpAuthLogin.Valid && r.SmtpAuthPasswd.Valid && len(r.SmtpAuthLogin.String) != 0 && len(r.SmtpAuthLogin.String) != 0 {
			var auth Auth
			_, auths := c.Extension("AUTH")
			if strings.Contains(auths, "CRAM-MD5") {
				auth = CRAMMD5Auth(r.SmtpAuthLogin.String, r.SmtpAuthPasswd.String)
			} else { // PLAIN
				auth = PlainAuth("", r.SmtpAuthLogin.String, r.SmtpAuthPasswd.String, r.RemoteHost)
			}

			if auth != nil {
				//if ok, _ := c.Extension("AUTH"); ok {
				err := c.Auth(auth)
				if err != nil {
					d.diePerm(err.Error())
					return
				}
			}
		}

		// MAIL FROM
		if err = c.Mail(d.qMsg.MailFrom); err != nil {
			msg := "connected to remote server " + c.RemoteIP + ":" + fmt.Sprintf("%d", c.RemotePort) + " but sender " + d.qMsg.MailFrom + " was rejected." + err.Error()
			scope.Log.Info(fmt.Sprintf("deliverd-remote %s: %s", d.id, msg))
			d.diePerm(msg)
			return
		}

		// RCPT TO
		if err = c.Rcpt(d.qMsg.RcptTo); err != nil {
			d.handleSmtpError(err.Error())
			return
		}

		// DATA
		dataPipe, err := c.Data()

		if err != nil {
			d.handleSmtpError(err.Error())
			return
		}
		// TODO one day: check if the size returned by copy is the same as mail size
		// TODO add X-Tmail-Deliverd-Id header
		// Parse raw email to add headers
		// - x-tmail-deliverd-id
		// - x-tmail-msg-id
		// - received

		msg, err := message.New(d.rawData)
		if err != nil {
			d.dieTemp(err.Error())
			return
		}

		msg.SetHeader("x-tmail-deliverd-id", d.id)
		msg.SetHeader("x-tmail-msg-id", d.qMsg.Key)
		*d.rawData, err = msg.GetRaw()
		if err != nil {
			d.dieTemp(err.Error())
			return
		}
		*d.rawData = append([]byte("Received: tmail deliverd; "+time.Now().Format(scope.Time822)+"\r\n"), *d.rawData...)
		dataBuf := bytes.NewBuffer(*d.rawData)
		_, err = io.Copy(dataPipe, dataBuf)
		if err != nil {
			d.dieTemp(err.Error())
			return
		}

		err = dataPipe.Close()
		// err existe toujours car c'est ce qui nous permet de récuperer la reponse du serveur distant
		// on parse err
		parts := strings.Split(err.Error(), "é")
		scope.Log.Info(fmt.Sprintf("deliverd-remote %s: remote server %s reply to data cmd: %s - %s", d.id, c.RemoteIP, parts[0], parts[1]))
		if len(parts) > 2 && len(parts[2]) != 0 {
			d.dieTemp(parts[2])
			return
		}

		// Bye
		err = c.Close()
		if err != nil {
			d.handleSmtpError(err.Error())
			return
		}
		d.dieOk()*/
	return
}

func (d *delivery) dieOk() {
	scope.Log.Info("deliverd-remote " + d.id + ": success.")
	if err := d.qMsg.Delete(); err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable remove message " + d.qMsg.Key + " from queue. " + err.Error())
	}
	d.nsqMsg.Finish()
}

// dieTemp die when a 4** error occured
func (d *delivery) dieTemp(msg string) {
	scope.Log.Info("deliverd " + d.id + ": temp failure - " + msg)
	if time.Since(d.qMsg.AddedAt) < time.Duration(scope.Cfg.GetDeliverdQueueLifetime())*time.Minute {
		d.requeue()
		return
	}
	msg += "\r\nI'm not going to try again, this message has been in the queue for too long."
	d.diePerm(msg)
}

// diePerm when a 5** error occured
func (d *delivery) diePerm(msg string) {
	scope.Log.Info("deliverd " + d.id + ": perm failure - " + msg)
	// bounce message
	d.bounce(msg)
	return
}

// discard remove a message from queue
func (d *delivery) discard() {
	scope.Log.Info("deliverd " + d.id + " discard message " + d.qMsg.Key)
	if err := d.qMsg.Delete(); err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable remove message " + d.qMsg.Key + " from queue. " + err.Error())
		d.requeue(1)
	} else {
		d.nsqMsg.Finish()
	}
	return
}

// bounce creates & enqueues a bounce message
func (d *delivery) bounce(errMsg string) {
	// If returnPath =="" -> double bounce -> discard
	if d.qMsg.ReturnPath == "" {
		scope.Log.Info("deliverd " + d.id + ": message from: " + d.qMsg.MailFrom + " to: " + d.qMsg.RcptTo + " double bounce: discarding")
		if err := d.qMsg.Delete(); err != nil {
			scope.Log.Error("deliverd " + d.id + ": unable remove message " + d.qMsg.Key + " from queue. " + err.Error())
			d.requeue(1)
		} else {
			d.nsqMsg.Finish()
		}
		return
	}

	// triple bounce
	if d.qMsg.ReturnPath == "#@[]" {
		scope.Log.Info("deliverd " + d.id + ": message from: " + d.qMsg.MailFrom + " to: " + d.qMsg.RcptTo + " triple bounce: discarding")
		if err := d.qMsg.Delete(); err != nil {
			scope.Log.Error("deliverd " + d.id + ": unable remove message " + d.qMsg.Key + " from queue. " + err.Error())
			d.requeue(1)
		} else {
			d.nsqMsg.Finish()
		}
		return
	}

	type templateData struct {
		Date        string
		Me          string
		RcptTo      string
		OriRcptTo   string
		ErrMsg      string
		BouncedMail string
	}

	// Si ça bounce car le mail a disparu de la queue:
	if d.rawData == nil {
		t := []byte("Raw mail was not found in the store")
		d.rawData = &t
	}

	tData := templateData{time.Now().Format(scope.Time822), scope.Cfg.GetMe(), d.qMsg.MailFrom, d.qMsg.RcptTo, errMsg, string(*d.rawData)}
	t, err := template.ParseFiles(path.Join(GetBasePath(), "tpl/bounce.tpl"))
	if err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable to bounce message " + d.qMsg.Key + " " + err.Error())
		d.requeue(3)
		return
	}

	bouncedMailBuf := new(bytes.Buffer)
	err = t.Execute(bouncedMailBuf, tData)
	if err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable to bounce message " + d.qMsg.Key + " " + err.Error())
		d.requeue(3)
		return
	}
	b, err := ioutil.ReadAll(bouncedMailBuf)
	if err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable to bounce message " + d.qMsg.Key + " " + err.Error())
		d.requeue(3)
		return
	}
	// enqueue
	envelope := message.Envelope{"", []string{d.qMsg.ReturnPath}}
	message, err := message.New(&b)
	if err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable to bounce message " + d.qMsg.Key + " " + err.Error())
		d.requeue(3)
		return
	}
	id, err := QueueAddMessage(message, envelope, "")
	if err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable to bounce message " + d.qMsg.Key + " " + err.Error())
		d.requeue(3)
		return
	}

	if err := d.qMsg.Delete(); err != nil {
		scope.Log.Error("deliverd " + d.id + ": unable remove bounced message " + d.qMsg.Key + " from queue. " + err.Error())
		d.requeue(1)
	} else {
		d.nsqMsg.Finish()
	}

	scope.Log.Info("deliverd " + d.id + ": message from: " + d.qMsg.MailFrom + " to: " + d.qMsg.RcptTo + " queued with id " + id + " for being bounced.")
	return
}

// requeue requeues the message increasing the delay
func (d *delivery) requeue(newStatus ...uint32) {
	var status uint32
	status = 2
	if len(newStatus) != 0 {
		status = newStatus[0]
	}

	// Si entre deux le status a changé
	//d.qMsg.UpdateFromDb()
	//si il y a eu un changement entre temps  discard or bounce
	//if d.qMsg.Status == 1 || d.qMsg.Status == 3 {
	//	return
	//}
	// Calcul du delais, pour le moment on accroit betement de 60 secondes a chaque tentative
	delay := time.Duration(d.nsqMsg.Attempts*60) * time.Second
	// Todo update next delivery en DB
	d.qMsg.NextDeliveryScheduledAt = time.Now().Add(delay)
	d.qMsg.Status = status
	d.qMsg.SaveInDb() // Todo: check error
	d.nsqMsg.RequeueWithoutBackoff(delay)
	return
}

// handleSmtpError handles SMTP error response
func (d *delivery) handleSmtpError(smtpErr string) {
	smtpResponse, err := parseSmtpResponse(smtpErr)
	if err != nil { // invalid smtp response
		d.dieTemp(err.Error())
	}
	if smtpResponse.Code > 499 {
		d.diePerm(smtpResponse.Msg)
	} else {
		d.dieTemp(smtpResponse.Msg)
	}
}

// getSmtpClient returns a smtp client
// On doit faire un choix de priorité entre les locales et les remotes
// La priorité sera basée sur l'ordre des remotes
// Donc on testes d'abord toutes les IP locales sur les remotes
func getSmtpClient(routes *[]Route) (*Client, *Route, error) {
	//var err error
	for _, route := range *routes {
		localIps := []net.IP{}
		remoteAddresses := []net.TCPAddr{}
		// no mix beetween & and |
		failover := strings.Count(route.LocalIp.String, "&") != 0
		roundRobin := strings.Count(route.LocalIp.String, "|") != 0

		if failover && roundRobin {
			return nil, &route, errors.New("mixing & and | are not allowed in localIP routes: " + route.LocalIp.String)
		}

		// Contient les IP sous forme de string
		var sIps []string

		// On a une seule IP locale
		if !failover && !roundRobin {
			sIps = append(sIps, route.LocalIp.String)
		} else { // multiple locales ips
			var sep string
			if failover {
				sep = "&"
			} else {
				sep = "|"
			}
			sIps = strings.Split(route.LocalIp.String, sep)

			// if roundRobin we need tu schuffle IP
			rSIps := make([]string, len(sIps))
			perm := rand.Perm(len(sIps))
			for i, v := range perm {
				rSIps[v] = sIps[i]
			}
			sIps = rSIps
			rSIps = nil
		}

		// IP string to net.IP
		for _, ipStr := range sIps {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, &route, errors.New("invalid IP " + ipStr + " found in localIp routes: " + route.LocalIp.String)
			}
			localIps = append(localIps, ip)
		}

		// On defini remoteAdresses

		//addr := net.TCPAddr{}
		// Hostname or IP
		ip := net.ParseIP(route.RemoteHost)
		if ip != nil { // ip
			remoteAddresses = append(remoteAddresses, net.TCPAddr{
				IP:   ip,
				Port: int(route.RemotePort.Int64),
			})
		} else { // hostname
			ips, err := net.LookupIP(route.RemoteHost)
			if err != nil {
				return nil, &route, err
			}
			for _, i := range ips {
				remoteAddresses = append(remoteAddresses, net.TCPAddr{
					IP:   i,
					Port: int(route.RemotePort.Int64),
				})
			}
		}

		// On essaye de trouver une route qui fonctionne
		for _, lIp := range localIps {
			for _, remoteAddr := range remoteAddresses {
				// on doit avopir de l'IPv4 en entré et sortie ou de l'IP6 en e/s
				if IsIpV4(lIp.String()) != IsIpV4(remoteAddr.IP.String()) {
					continue
				}
				// TODO timeout en config
				c, err := Dialz(&remoteAddr, lIp.String(), scope.Cfg.GetMe(), 30)
				if err == nil {
					return c, &route, nil
				} else {
					scope.Log.Debug("deliverd.getSmtpClient: unable to get a client", lIp, "->", remoteAddr.IP.String(), ":", remoteAddr.Port, "-", err)
				}
			}
		}
	}
	// All routes have been tested -> Fail !
	return nil, nil, errors.New("deliverd.getSmtpClient: unable to get a client, all routes have been tested")
}

// smtpResponse represents a SMTP response
type smtpResponse struct {
	Code int
	Msg  string
}

// parseSmtpResponse parse an smtp response
// warning ça parse juste une ligne et ne tient pas compte des continued (si line[4]=="-")
func parseSmtpResponse(line string) (response smtpResponse, err error) {
	err = errors.New("invalid smtp response from remote server: " + line)
	if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
		return
	}
	response.Code, err = strconv.Atoi(line[0:3])
	if err != nil {
		return
	}
	response.Msg = line[4:]
	return
}