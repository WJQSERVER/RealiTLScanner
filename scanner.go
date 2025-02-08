package main

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func ScanTLS(host Host, out chan<- string, geo *Geo) {
	if host.IP == nil {
		ip, err := LookupIP(host.Origin)
		if err != nil {
			slog.Debug("Failed to get IP from the origin", "origin", host.Origin, "err", err)
			return
		}
		host.IP = ip
	}

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(timeout)*time.Second)
	if err != nil {
		slog.Debug("Cannot dial", "target", hostPort)
		return
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		slog.Error("Error setting deadline", "err", err)
		return
	}

	// 使用utls配置替换标准TLS配置
	tlsCfg := &utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []utls.CurveID{utls.X25519},
	}

	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}

	// 创建utls客户端并选择Chrome的指纹特征
	clientHelloID := utls.HelloChrome_Auto // 自动选择最新Chrome版本
	c := utls.UClient(conn, tlsCfg, clientHelloID)
	defer c.Close()

	// 执行TLS握手
	err = c.Handshake()
	if err != nil {
		slog.Debug("TLS handshake failed", "target", hostPort)
		return
	}

	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	domain := ""
	issuers := ""
	if len(state.PeerCertificates) > 0 {
		domain = state.PeerCertificates[0].Subject.CommonName
		issuers = strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	}

	log := slog.Info
	feasible := true
	geoCode := geo.GetGeo(host.IP)

	if state.Version != utls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{host.IP.String(), host.Origin, domain, "\"" + issuers + "\"", geoCode}, ",") + "\n"
	}

	// 转换TLS版本号为标准名称
	tlsVersion := "Unknown"
	switch state.Version {
	case utls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	case utls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	}

	log("Connected to target",
		"feasible", feasible,
		"ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tlsVersion,
		"alpn", alpn,
		"cert-domain", domain,
		"cert-issuer", issuers,
		"geo", geoCode)
}
