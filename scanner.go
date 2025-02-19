package main

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSSettings 结构体封装了 TLS 配置参数。
type TLSSettings struct {
	Timeout         int
	Port            int
	EnableIPv6      bool
	ChromeAutoHello bool
}

// ScanResult 结构体用于存储扫描结果，字段名更适合 JSON 输出。
type ScanResult struct {
	IP         string `json:"ip"`           // IP 地址，字符串格式
	Origin     string `json:"origin"`       // 原始输入
	Domain     string `json:"cert_domain"`  // 证书域名
	Issuers    string `json:"cert_issuers"` // 证书颁发者
	GeoCode    string `json:"geo_code"`     // 地理位置代码
	Feasible   bool   `json:"feasible"`     // 是否可行 (符合 TLS 1.3 + h2)
	TLSVersion string `json:"tls_version"`  // TLS 版本
	ALPN       string `json:"alpn"`         // ALPN 协议
}

// ScanTLS 函数对指定主机执行 TLS 扫描。
func ScanTLS(host Host, outputFile *OutputFileWriter, geo *Geo, settings TLSSettings) { // 修改 out 参数类型
	if !host.IP.IsValid() {
		ip, err := LookupIP(host.Origin, settings.EnableIPv6)
		if err != nil {
			slog.Debug("获取域名 IP 地址失败", "origin", host.Origin, "错误", err)
			return
		}
		host.IP = ip
	}

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(settings.Port))

	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(settings.Timeout)*time.Second)
	if err != nil {
		slog.Debug("无法连接目标", "target", hostPort, "错误", err)
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(time.Duration(settings.Timeout) * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		slog.Error("设置连接截止时间错误", "target", hostPort, "错误", err)
		return
	}

	tlsCfg := &utls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []utls.CurveID{utls.X25519},
		ServerName:         host.Origin,
	}

	if host.Type != HostTypeDomain {
		tlsCfg.ServerName = host.IP.String()
	}

	var clientHelloID utls.ClientHelloID
	if settings.ChromeAutoHello {
		clientHelloID = utls.HelloChrome_Auto
	} else {
		clientHelloID = utls.HelloChrome_120
	}

	uConn := utls.UClient(conn, tlsCfg, clientHelloID)
	defer uConn.Close()

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	err = uConn.HandshakeContext(ctx)
	if err != nil {
		slog.Debug("TLS 握手失败", "target", hostPort, "错误", err)
		return
	}

	state := uConn.ConnectionState()
	alpn := state.NegotiatedProtocol
	domain := ""
	issuers := ""

	if len(state.PeerCertificates) > 0 {
		domain = state.PeerCertificates[0].Subject.CommonName
		issuers = strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	}

	logLevel := slog.LevelInfo
	feasible := true
	geoCode := geo.GetGeoNetIP(host.IP)

	scanResult := ScanResult{ // 创建 ScanResult 结构体
		IP:         host.IP.String(),
		Origin:     host.Origin,
		Domain:     domain,
		Issuers:    issuers,
		GeoCode:    geoCode,
		Feasible:   feasible,
		TLSVersion: getTLSVersionName(state.Version),
		ALPN:       alpn,
	}

	if state.Version != utls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		logLevel = slog.LevelDebug
		feasible = false
		scanResult.Feasible = feasible // 确保 Feasible 字段被正确设置
		outputFile.outFail(scanResult) // 调用 outFail 方法
	} else {
		outputFile.outOK(scanResult) // 调用 outOK 方法
	}

	slog.Log(context.Background(), logLevel, "连接到目标",
		"feasible", feasible,
		"ip", host.IP.String(),
		"origin", host.Origin,
		"tls", getTLSVersionName(state.Version),
		"alpn", alpn,
		"cert-domain", domain,
		"cert-issuer", issuers,
		"geo", geoCode)
}

// getTLSVersionName 函数将 uTLS 版本常量转换为字符串表示形式。
func getTLSVersionName(version uint16) string {
	switch version {
	case utls.VersionTLS13:
		return "TLS 1.3"
	case utls.VersionTLS12:
		return "TLS 1.2"
	default:
		return "Unknown"
	}
}
