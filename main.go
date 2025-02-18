package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// 定义命令行标志
var (
	addressFlag      string
	inputFileFlag    string
	portFlag         int
	threadFlag       int
	outputFileFlag   string
	timeoutFlag      int
	verboseFlag      bool
	enableIPv6Flag   bool
	urlFlag          string
	chromeAutoFlag   bool
	outputFormatFlag string // 新增输出格式标志
)

func init() {
	flag.StringVar(&addressFlag, "addr", "", "指定 IP, IP CIDR 或域名进行扫描")
	flag.StringVar(&inputFileFlag, "in", "", "包含 IP, CIDR 或域名的文件路径")
	flag.IntVar(&portFlag, "port", 443, "HTTPS 端口")
	flag.IntVar(&threadFlag, "thread", runtime.NumCPU(), "并发任务数 (默认: CPU 核心数)")
	flag.StringVar(&outputFileFlag, "out", "out", "输出文件名前缀 (不包含扩展名)") // 修改默认输出文件名前缀
	flag.IntVar(&timeoutFlag, "timeout", 10, "每次检查的超时秒数")
	flag.BoolVar(&verboseFlag, "v", false, "详细输出 (debug 日志)")
	flag.BoolVar(&enableIPv6Flag, "46", false, "启用 IPv6 扫描")
	flag.StringVar(&urlFlag, "url", "", "从 URL 抓取域名列表")
	flag.BoolVar(&chromeAutoFlag, "chrome-auto", true, "TLS 握手使用 HelloChrome_Auto")
	flag.StringVar(&outputFormatFlag, "format", "json", "输出格式 (json, readable)") // 新增输出格式选项

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s 使用方法:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "TLS 扫描器，用于识别具有特定配置的服务器。")
		fmt.Fprintln(os.Stderr, "\n选项:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n例子:")
		fmt.Fprintln(os.Stderr, "  扫描单个 IP: go run main.go -addr 1.1.1.1 -format json -out results")
		fmt.Fprintln(os.Stderr, "  从文件扫描 IP 列表: go run main.go -in hosts.txt -thread 10 -format readable -out detailed_results")
		fmt.Fprintln(os.Stderr, "  扫描 URL 域名: go run main.go -url https://example.com -format json -out domains")
	}
}

/*
func main() {
	flag.Parse()

	// 清除代理环境变量
	envVars := []string{"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
	for _, envVar := range envVars {
		_ = os.Unsetenv(envVar)
	}

	// 配置日志
	logLevel := slog.LevelInfo
	if verboseFlag {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	// 验证输入源
	inputSources := []string{addressFlag, inputFileFlag, urlFlag}
	if !ExistOnlyOne(inputSources) {
		slog.Error("请仅指定 -addr, -in, 或 -url 中的一个")
		flag.Usage()
		os.Exit(1)
	}

	// 输出写入器设置
	var outChannel chan<- ScanResult
	var jsonFile io.Writer
	var readableFile io.Writer

	if outputFileFlag != "" {
		if outputFormatFlag == "json" {
			f, err := os.OpenFile(outputFileFlag+".json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0777)
			if err != nil {
				slog.Error("打开 JSON 输出文件错误", "path", outputFileFlag+".json", "error", err)
				os.Exit(1)
			}
			defer f.Close()
			jsonFile = f
			outChannel = OutWriterJSON(jsonFile) // 使用 JSON 输出写入器
		} else if outputFormatFlag == "readable" {
			f, err := os.OpenFile(outputFileFlag+".txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0777)
			if err != nil {
				slog.Error("打开易读文本输出文件错误", "path", outputFileFlag+".txt", "error", err)
				os.Exit(1)
			}
			defer f.Close()
			readableFile = f
			outChannel = OutWriterReadable(readableFile) // 使用易读文本输出写入器
		} else {
			slog.Error("不支持的输出格式", "format", outputFormatFlag)
			flag.Usage()
			os.Exit(1)
		}
	} else {
		outChannel = OutWriterJSON(io.Discard) // 默认丢弃输出，但初始化 JSON 输出写入器以避免空指针
		readableFile = io.Discard
		jsonFile = io.Discard
	}
	defer close(outChannel)

	// 主机输入 channel 设置
	var hostChan <-chan Host
	switch {
	case addressFlag != "":
		hostChan = IterateAddr(addressFlag, enableIPv6Flag)
	case inputFileFlag != "":
		f, err := os.Open(inputFileFlag)
		if err != nil {
			slog.Error("打开输入文件错误", "path", inputFileFlag, "error", err)
			os.Exit(1)
		}
		defer f.Close()
		hostChan = Iterate(f, enableIPv6Flag)
	case urlFlag != "":
		slog.Info("从 URL 获取域名列表", "url", urlFlag)
		resp, err := http.Get(urlFlag)
		if err != nil {
			slog.Error("HTTP 请求失败", "url", urlFlag, "error", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("读取响应体失败", "url", urlFlag, "error", err)
			os.Exit(1)
		}
		slog.Debug("URL 响应", "status", resp.StatusCode, "body_length", len(bodyBytes))

		domainRegex := regexp.MustCompile(`(http|https)://(.*?)[/"<>\s]+`)
		matches := domainRegex.FindAllStringSubmatch(string(bodyBytes), -1)
		var domains []string
		for _, match := range matches {
			domains = append(domains, match[2])
		}
		domains = RemoveDuplicateStr(domains)
		slog.Info("从 URL 解析域名", "count", len(domains))
		hostChan = Iterate(strings.NewReader(strings.Join(domains, "\n")), enableIPv6Flag)
	default:
		slog.Error("未指定输入源")
		flag.Usage()
		os.Exit(1)
	}

	geoData := NewGeo()

	var wg sync.WaitGroup
	wg.Add(threadFlag)

	tlsSettings := TLSSettings{
		Timeout:         timeoutFlag,
		Port:            portFlag,
		EnableIPv6:      enableIPv6Flag,
		ChromeAutoHello: chromeAutoFlag,
	}

	slog.Info("开始 TLS 扫描", "threads", threadFlag, "timeout", timeoutFlag, "port", portFlag, "output", outputFileFlag, "format", outputFormatFlag)
	startTime := time.Now()

	for i := 0; i < threadFlag; i++ {
		go func() {
			defer wg.Done()
			for host := range hostChan {
				ScanTLS(host, outChannel, geoData, tlsSettings)
			}
		}()
	}

	wg.Wait()
	elapsedTime := time.Since(startTime)
	slog.Info("TLS 扫描完成", "耗时", elapsedTime.String())
}
*/

func main() {
	flag.Parse()

	// 配置日志
	logLevel := slog.LevelInfo
	if verboseFlag {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	// 验证输入源
	inputSources := []string{addressFlag, inputFileFlag, urlFlag}
	if !ExistOnlyOne(inputSources) {
		slog.Error("请仅指定 -addr, -in, 或 -url 中的一个")
		flag.Usage()
		os.Exit(1)
	}

	// 初始化输出写入器
	outChannel, closeOutput, err := InitOutputWriter(outputFileFlag, outputFormatFlag)
	if err != nil {
		slog.Error("初始化输出写入器失败", "error", err)
		os.Exit(1)
	}
	defer closeOutput() // 确保资源释放
	defer close(outChannel)

	// 主机输入 channel 设置
	var hostChan <-chan Host
	switch {
	case addressFlag != "":
		hostChan = IterateAddr(addressFlag, enableIPv6Flag)
	case inputFileFlag != "":
		f, err := os.Open(inputFileFlag)
		if err != nil {
			slog.Error("打开输入文件错误", "path", inputFileFlag, "error", err)
			os.Exit(1)
		}
		defer f.Close()
		hostChan = Iterate(f, enableIPv6Flag)
	case urlFlag != "":
		slog.Info("从 URL 获取域名列表", "url", urlFlag)
		resp, err := http.Get(urlFlag)
		if err != nil {
			slog.Error("HTTP 请求失败", "url", urlFlag, "error", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("读取响应体失败", "url", urlFlag, "error", err)
			os.Exit(1)
		}
		slog.Debug("URL 响应", "status", resp.StatusCode, "body_length", len(bodyBytes))

		domainRegex := regexp.MustCompile(`(http|https)://(.*?)[/"<>\s]+`)
		matches := domainRegex.FindAllStringSubmatch(string(bodyBytes), -1)
		var domains []string
		for _, match := range matches {
			domains = append(domains, match[2])
		}
		domains = RemoveDuplicateStr(domains)
		slog.Info("从 URL 解析域名", "count", len(domains))
		hostChan = Iterate(strings.NewReader(strings.Join(domains, "\n")), enableIPv6Flag)
	default:
		slog.Error("未指定输入源")
		flag.Usage()
		os.Exit(1)
	}

	geoData := NewGeo()

	var wg sync.WaitGroup
	wg.Add(threadFlag)

	tlsSettings := TLSSettings{
		Timeout:         timeoutFlag,
		Port:            portFlag,
		EnableIPv6:      enableIPv6Flag,
		ChromeAutoHello: chromeAutoFlag,
	}

	slog.Info("开始 TLS 扫描", "threads", threadFlag, "timeout", timeoutFlag, "port", portFlag, "output", outputFileFlag, "format", outputFormatFlag)
	startTime := time.Now()

	for i := 0; i < threadFlag; i++ {
		go func() {
			defer wg.Done()
			for host := range hostChan {
				ScanTLS(host, outChannel, geoData, tlsSettings)
			}
		}()
	}

	wg.Wait()
	elapsedTime := time.Since(startTime)
	slog.Info("TLS 扫描完成", "耗时", elapsedTime.String())
}
