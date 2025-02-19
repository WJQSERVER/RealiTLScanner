package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	outputFormatFlag string // 输出格式标志
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
	flag.StringVar(&outputFormatFlag, "format", "json", "输出格式 (json, readable)") // 输出格式标志

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s 使用方法:\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "TLS 扫描器，用于识别具有特定配置的服务器。")
		fmt.Fprintln(os.Stderr, "\n选项:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\n例子:")
		fmt.Fprintln(os.Stderr, " 扫描单个 IP: go run main.go -addr 1.1.1.1 -format json -out results")
		fmt.Fprintln(os.Stderr, " 从文件扫描 IP 列表: go run main.go -in hosts.txt -thread 10 -format readable -out detailed_results")
		fmt.Fprintln(os.Stderr, " 扫描 URL 域名: go run main.go -url https://example.com -format json -out domains")
	}
}

func main() {
	flag.Parse()

	// 清除代理环境变量
	envVars := []string{"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
	for _, envVarName := range envVars {
		_ = os.Unsetenv(envVarName)
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

	// 输出文件和写入器设置
	var outputFile io.Writer
	var outputFileWriter *OutputFileWriter
	var f *os.File // Declare f as *os.File

	if outputFileFlag != "" {
		var filename string
		if outputFormatFlag == "json" {
			filename = outputFileFlag + ".json"
		} else if outputFormatFlag == "readable" {
			filename = outputFileFlag + ".txt"
		} else {
			slog.Error("不支持的输出格式", "format", outputFormatFlag)
			flag.Usage()
			os.Exit(1)
		}

		f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0777) // Assign to f
		if err != nil {
			slog.Error("打开输出文件错误", "path", filename, "error", err)
			os.Exit(1)
		}
		outputFile = f // Assign f (which is *os.File) to outputFile (io.Writer)
		outputFileWriter = NewOutputFileWriter(outputFile, outputFormatFlag)
		defer func() {
			outputFileWriter.WriteResults()
			outputFileWriter.Close()
			f.Close() // Call f.Close() which is *os.File
		}()
	} else {
		outputFile = io.Discard
		outputFileWriter = NewOutputFileWriter(outputFile, outputFormatFlag)
	}

	// 主机输入 channel 设置
	var hostChan <-chan Host
	switch {
	case addressFlag != "":
		hostChan = IterateAddr(addressFlag, enableIPv6Flag)
	case inputFileFlag != "":
		file, err := os.Open(inputFileFlag) // 避免变量名冲突，使用 file
		if err != nil {
			slog.Error("打开输入文件错误", "path", inputFileFlag, "error", err)
			os.Exit(1)
		}
		defer file.Close()
		hostChan = Iterate(file, enableIPv6Flag)
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

	// 优雅关闭处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		slog.Info("接收到信号, 开始优雅关闭...", "signal", sig)
		slog.Debug("等待扫描任务完成...")
		wg.Wait() // 等待所有扫描任务完成
		slog.Debug("扫描任务完成, 准备写入结果...")
		outputFileWriter.WriteResults() // 确保退出前写入剩余结果
		outputFileWriter.Close()        // 关闭 OutputFileWriter (刷新缓冲区)
		if outputFileFlag != "" {       // Only close the file if outputFileFlag is not empty
			f.Close() // 关闭文件
		}
		slog.Info("优雅关闭完成.")
		os.Exit(0) // 正常退出
	}()

	for i := 0; i < threadFlag; i++ {
		go func() {
			defer wg.Done()
			for host := range hostChan {
				ScanTLS(host, outputFileWriter, geoData, tlsSettings) // 传递 OutputFileWriter
			}
		}()
	}

	wg.Wait() // 等待所有 worker 完成

	elapsedTime := time.Since(startTime)
	slog.Info("TLS 扫描完成", "耗时", elapsedTime.String())

	if outputFileFlag == "" { //  如果没指定输出文件，在程序正常结束时，也需要将结果输出到 stdout
		outputFileWriter.WriteResults() //  将结果输出到 discard (stdout)
	}
}
