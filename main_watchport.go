package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	interval  = flag.Float64("n", 5.0, "갱신 간격 (초)")
	portSpec  = flag.String("p", "", "포트 또는 포트 범위 (예: 80, 8000-9000, 80,443,8080)")
	sortBy    = flag.String("s", "port", "정렬 기준: port, pid, name, proto")
	descOrder = flag.Bool("d", false, "내림차순 정렬")
	showAll   = flag.Bool("a", false, "모든 상태 표시 (기본: LISTEN만)")
	tcpOnly   = flag.Bool("t", false, "TCP만 표시")
	udpOnly   = flag.Bool("u", false, "UDP만 표시")
	noHeader      = flag.Bool("no-header", false, "헤더 숨기기")
	ipv4Only      = flag.Bool("4", false, "IPv4만 표시")
	ipv6Only      = flag.Bool("6", false, "IPv6만 표시")
	localFilter   = flag.String("L", "", "Local 주소 필터 (포함, 콤마 구분)")
	remoteFilter  = flag.String("R", "", "Remote 주소 필터 (포함, 콤마 구분)")
	excludeLocal  = flag.String("xL", "", "Local 주소 제외 필터 (콤마 구분)")
	excludeRemote = flag.String("xR", "", "Remote 주소 제외 필터 (콤마 구분)")
	grepFilter    = flag.String("g", "", "전체 라인 필터 (포함, 콤마 구분)")
	excludeGrep   = flag.String("xg", "", "전체 라인 제외 필터 (콤마 구분)")
)

var prevCols, prevRows int
var startTime time.Time

var (
	paused    int32
	lastConns []PortInfo
	displayMu sync.Mutex
	exitOnce  sync.Once
)

// PortInfo 포트 정보 구조체
type PortInfo struct {
	Protocol    string
	LocalAddr   string
	LocalPort   uint32
	RemoteAddr  string
	RemotePort  uint32
	Status      string
	PID         int32
	ProcessName string
}

// PortRange 포트 범위 구조체
type PortRange struct {
	Start uint32
	End   uint32
}

// colWidths 터미널 폭에 따른 동적 컬럼 너비
type colWidths struct {
	local   int
	remote  int
	process int
	total   int
}

func calcColWidths(termCols int) colWidths {
	// 고정: PROTO(6)+sp(1)+PORT(6)+sp(2)+sp(1)+sp(1)+STATUS(12)+sp(1)+PID(8)+sp(2) = 40
	const fixedWidth = 40
	const minLocal = 15
	const minRemote = 15
	const minProcess = 10

	if termCols < fixedWidth+minLocal+minRemote+minProcess {
		termCols = fixedWidth + minLocal + minRemote + minProcess
	}

	remaining := termCols - fixedWidth
	procW := remaining / 3
	if procW > 45 {
		procW = 45
	}
	if procW < minProcess {
		procW = minProcess
	}
	addrW := (remaining - procW) / 2

	return colWidths{local: addrW, remote: addrW, process: procW, total: termCols}
}


// parsePortSpec 포트 지정 파싱 (예: "80", "8000-9000", "80,443,8080")
func parsePortSpec(spec string) ([]PortRange, error) {
	if spec == "" {
		return nil, nil // 전체 포트
	}

	var ranges []PortRange
	parts := strings.Split(spec, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// 범위 (예: 8000-9000)
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("잘못된 포트 범위: %s", part)
			}
			start, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("잘못된 포트 번호: %s", rangeParts[0])
			}
			end, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("잘못된 포트 번호: %s", rangeParts[1])
			}
			if start > end {
				start, end = end, start
			}
			ranges = append(ranges, PortRange{Start: uint32(start), End: uint32(end)})
		} else {
			// 단일 포트
			port, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("잘못된 포트 번호: %s", part)
			}
			ranges = append(ranges, PortRange{Start: uint32(port), End: uint32(port)})
		}
	}

	return ranges, nil
}

// isPortInRange 포트가 범위에 포함되는지 확인
func isPortInRange(port uint32, ranges []PortRange) bool {
	if len(ranges) == 0 {
		return true // 범위가 지정되지 않으면 모든 포트
	}
	for _, r := range ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

// getProcessName PID로 프로세스 이름 조회
func getProcessName(pid int32) string {
	if pid == 0 {
		return "-"
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return "-"
	}
	name, err := p.Name()
	if err != nil {
		return "-"
	}
	return name
}

// statusToString 연결 상태를 문자열로 변환
func statusToString(status string) string {
	switch status {
	case "LISTEN":
		return "LISTENING"
	case "ESTABLISHED":
		return "ESTABLISHED"
	case "TIME_WAIT":
		return "TIME_WAIT"
	case "CLOSE_WAIT":
		return "CLOSE_WAIT"
	case "SYN_SENT":
		return "SYN_SENT"
	case "SYN_RECV":
		return "SYN_RECV"
	case "FIN_WAIT1":
		return "FIN_WAIT1"
	case "FIN_WAIT2":
		return "FIN_WAIT2"
	case "LAST_ACK":
		return "LAST_ACK"
	case "CLOSING":
		return "CLOSING"
	case "NONE":
		return "NONE"
	default:
		return status
	}
}

// isIPv6 주소가 IPv6인지 확인
func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

// matchIPFilter IPv4/IPv6 필터 통과 여부
func matchIPFilter(ip string, v4Only, v6Only bool) bool {
	if v4Only && isIPv6(ip) {
		return false
	}
	if v6Only && !isIPv6(ip) {
		return false
	}
	return true
}

// matchAddrFilter 주소 필터 매칭 (포함/제외)
func matchAddrFilter(addr string, includeFilter, excludeFilter string) bool {
	// 포함 필터: 지정된 패턴 중 하나라도 포함되어야 통과
	if includeFilter != "" {
		matched := false
		for _, pattern := range strings.Split(includeFilter, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" && strings.Contains(addr, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// 제외 필터: 지정된 패턴 중 하나라도 포함되면 제외
	if excludeFilter != "" {
		for _, pattern := range strings.Split(excludeFilter, ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern != "" && strings.Contains(addr, pattern) {
				return false
			}
		}
	}

	return true
}

// portInfoLine PortInfo를 검색용 한 줄 문자열로 변환
func portInfoLine(p *PortInfo) string {
	return fmt.Sprintf("%s %d %s:%d %s:%d %s %d %s",
		p.Protocol, p.LocalPort, p.LocalAddr, p.LocalPort,
		p.RemoteAddr, p.RemotePort, p.Status, p.PID, p.ProcessName)
}

// matchLineFilter 전체 라인 필터 매칭 (포함/제외)
func matchLineFilter(line string, includeFilter, excludeFilter string) bool {
	line = strings.ToLower(line)

	if includeFilter != "" {
		matched := false
		for _, pattern := range strings.Split(includeFilter, ",") {
			pattern = strings.TrimSpace(strings.ToLower(pattern))
			if pattern != "" && strings.Contains(line, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if excludeFilter != "" {
		for _, pattern := range strings.Split(excludeFilter, ",") {
			pattern = strings.TrimSpace(strings.ToLower(pattern))
			if pattern != "" && strings.Contains(line, pattern) {
				return false
			}
		}
	}

	return true
}

// getConnections 연결 목록 조회
func getConnections(portRanges []PortRange, tcpOnly, udpOnly, listenOnly, v4Only, v6Only bool, lFilter, rFilter, xlFilter, xrFilter, gFilter, xgFilter string) ([]PortInfo, error) {
	var result []PortInfo

	// TCP 연결
	if !udpOnly {
		tcpConns, err := net.Connections("tcp")
		if err != nil {
			return nil, err
		}

		for _, conn := range tcpConns {
			// LISTEN 필터
			if listenOnly && conn.Status != "LISTEN" {
				continue
			}

			// 포트 범위 필터
			if !isPortInRange(conn.Laddr.Port, portRanges) {
				continue
			}

			// IPv4/IPv6 필터
			if !matchIPFilter(conn.Laddr.IP, v4Only, v6Only) {
				continue
			}

			// Local 주소 필터
			if !matchAddrFilter(conn.Laddr.IP, lFilter, xlFilter) {
				continue
			}

			// Remote 주소 필터
			if !matchAddrFilter(conn.Raddr.IP, rFilter, xrFilter) {
				continue
			}

			info := PortInfo{
				Protocol:    "TCP",
				LocalAddr:   conn.Laddr.IP,
				LocalPort:   conn.Laddr.Port,
				RemoteAddr:  conn.Raddr.IP,
				RemotePort:  conn.Raddr.Port,
				Status:      statusToString(conn.Status),
				PID:         conn.Pid,
				ProcessName: getProcessName(conn.Pid),
			}

			// 전체 라인 grep 필터
			if !matchLineFilter(portInfoLine(&info), gFilter, xgFilter) {
				continue
			}

			result = append(result, info)
		}
	}

	// UDP 연결
	if !tcpOnly {
		udpConns, err := net.Connections("udp")
		if err != nil {
			return nil, err
		}

		for _, conn := range udpConns {
			// 포트 범위 필터
			if !isPortInRange(conn.Laddr.Port, portRanges) {
				continue
			}

			// IPv4/IPv6 필터
			if !matchIPFilter(conn.Laddr.IP, v4Only, v6Only) {
				continue
			}

			// Local 주소 필터
			if !matchAddrFilter(conn.Laddr.IP, lFilter, xlFilter) {
				continue
			}

			// Remote 주소 필터
			if !matchAddrFilter(conn.Raddr.IP, rFilter, xrFilter) {
				continue
			}

			info := PortInfo{
				Protocol:    "UDP",
				LocalAddr:   conn.Laddr.IP,
				LocalPort:   conn.Laddr.Port,
				RemoteAddr:  conn.Raddr.IP,
				RemotePort:  conn.Raddr.Port,
				Status:      "*",
				PID:         conn.Pid,
				ProcessName: getProcessName(conn.Pid),
			}

			// 전체 라인 grep 필터
			if !matchLineFilter(portInfoLine(&info), gFilter, xgFilter) {
				continue
			}

			result = append(result, info)
		}
	}

	return result, nil
}

// sortConnections 연결 정렬
func sortConnections(conns []PortInfo, sortBy string, desc bool) {
	sort.Slice(conns, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "port":
			less = conns[i].LocalPort < conns[j].LocalPort
		case "pid":
			less = conns[i].PID < conns[j].PID
		case "name":
			less = strings.ToLower(conns[i].ProcessName) < strings.ToLower(conns[j].ProcessName)
		case "proto":
			less = conns[i].Protocol < conns[j].Protocol
		case "status":
			less = conns[i].Status < conns[j].Status
		default:
			less = conns[i].LocalPort < conns[j].LocalPort
		}
		if desc {
			return !less
		}
		return less
	})
}

func formatElapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatElapsedShort(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	if m > 0 {
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", int(d.Seconds())%60)
}

func printHeader(portSpec string, interval float64, count int, listenOnly bool, cw colWidths) {
	elapsed := formatElapsed(time.Since(startTime))
	elapsedShort := formatElapsedShort(time.Since(startTime))
	mode := "LISTEN only"
	if !listenOnly {
		mode = "All states"
	}
	portDisplay := portSpec
	if portDisplay == "" {
		portDisplay = "ALL"
	}
	ipFilter := "IPv4+IPv6"
	if *ipv4Only {
		ipFilter = "IPv4"
	} else if *ipv6Only {
		ipFilter = "IPv6"
	}
	// 주소 필터 정보
	addrFilter := ""
	if *localFilter != "" {
		addrFilter += fmt.Sprintf(" | L:%s", *localFilter)
	}
	if *excludeLocal != "" {
		addrFilter += fmt.Sprintf(" | -L:%s", *excludeLocal)
	}
	if *remoteFilter != "" {
		addrFilter += fmt.Sprintf(" | R:%s", *remoteFilter)
	}
	if *excludeRemote != "" {
		addrFilter += fmt.Sprintf(" | -R:%s", *excludeRemote)
	}
	if *grepFilter != "" {
		addrFilter += fmt.Sprintf(" | grep:%s", *grepFilter)
	}
	if *excludeGrep != "" {
		addrFilter += fmt.Sprintf(" | -grep:%s", *excludeGrep)
	}

	w := cw.total

	// 폭에 맞춰 단계별로 정보 축소
	full := fmt.Sprintf("WatchPort [%s] | Ports: %s | %s | Mode: %s%s | Interval: %.1fs | Found: %d",
		elapsed, portDisplay, ipFilter, mode, addrFilter, interval, count)
	if len(full) <= w {
		fmt.Printf("\033[1;36mWatchPort\033[0m [\033[1;33m%s\033[0m] | Ports: \033[1;33m%s\033[0m | %s | Mode: %s%s | Interval: %.1fs | Found: \033[1;32m%d\033[0m\n",
			elapsed, portDisplay, ipFilter, mode, addrFilter, interval, count)
	} else if len(fmt.Sprintf("WatchPort [%s] | Ports: %s | %s | Mode: %s | Interval: %.1fs | Found: %d",
		elapsed, portDisplay, ipFilter, mode, interval, count)) <= w {
		// 주소 필터 제거
		fmt.Printf("\033[1;36mWatchPort\033[0m [\033[1;33m%s\033[0m] | Ports: \033[1;33m%s\033[0m | %s | Mode: %s | Interval: %.1fs | Found: \033[1;32m%d\033[0m\n",
			elapsed, portDisplay, ipFilter, mode, interval, count)
	} else if len(fmt.Sprintf("WatchPort [%s] | Ports: %s | %s | %s | Found: %d",
		elapsed, portDisplay, ipFilter, mode, count)) <= w {
		// Interval 제거
		fmt.Printf("\033[1;36mWatchPort\033[0m [\033[1;33m%s\033[0m] | Ports: \033[1;33m%s\033[0m | %s | %s | Found: \033[1;32m%d\033[0m\n",
			elapsed, portDisplay, ipFilter, mode, count)
	} else if len(fmt.Sprintf("WatchPort [%s] | Ports: %s | %s | Found: %d",
		elapsed, portDisplay, mode, count)) <= w {
		// IP 필터 제거
		fmt.Printf("\033[1;36mWatchPort\033[0m [\033[1;33m%s\033[0m] | Ports: \033[1;33m%s\033[0m | %s | Found: \033[1;32m%d\033[0m\n",
			elapsed, portDisplay, mode, count)
	} else if len(fmt.Sprintf("WatchPort [%s] | P:%s | Found: %d",
		elapsedShort, portDisplay, count)) <= w {
		// Mode 제거 + elapsed 축약
		fmt.Printf("\033[1;36mWatchPort\033[0m [\033[1;33m%s\033[0m] | P:\033[1;33m%s\033[0m | Found: \033[1;32m%d\033[0m\n",
			elapsedShort, portDisplay, count)
	} else {
		// 최소: WatchPort + Found
		fmt.Printf("\033[1;36mWatchPort\033[0m | \033[1;32m%d\033[0m\n", count)
	}

	fmt.Println(strings.Repeat("-", w))
}

func printTableHeader(cw colWidths) {
	fmt.Printf("\033[1;37m%-6s %6s  %-*s %-*s %-12s %8s  %-*s\033[0m\n",
		"PROTO", "PORT", cw.local, "LOCAL ADDRESS", cw.remote, "REMOTE ADDRESS", "STATUS", "PID", cw.process, "PROCESS")
}

func printConnection(p PortInfo, cw colWidths) {
	// 로컬 주소
	localAddr := fmt.Sprintf("%s:%d", p.LocalAddr, p.LocalPort)

	// 원격 주소
	remoteAddr := "*:*"
	if p.RemoteAddr != "" && p.RemotePort > 0 {
		remoteAddr = fmt.Sprintf("%s:%d", p.RemoteAddr, p.RemotePort)
	}

	// 프로세스 이름
	procName := p.ProcessName

	// 프로토콜 색상
	protoColor := "\033[1;34m" // 파란색 (TCP)
	if p.Protocol == "UDP" {
		protoColor = "\033[1;35m" // 보라색 (UDP)
	}

	// 상태 색상
	statusColor := "\033[0m"
	switch p.Status {
	case "LISTENING":
		statusColor = "\033[1;32m" // 초록색
	case "ESTABLISHED":
		statusColor = "\033[1;33m" // 노란색
	case "TIME_WAIT", "CLOSE_WAIT":
		statusColor = "\033[1;31m" // 빨간색
	}

	// PID 표시
	pidStr := "-"
	if p.PID > 0 {
		pidStr = fmt.Sprintf("%d", p.PID)
	}

	fmt.Printf("%s%-6s\033[0m %6d  %-*s %-*s %s%-12s\033[0m %8s  %-*s\n",
		protoColor, p.Protocol,
		p.LocalPort,
		cw.local, localAddr,
		cw.remote, remoteAddr,
		statusColor, p.Status,
		pidStr,
		cw.process, procName,
	)
}

func display(portRanges []PortRange, firstRun bool) {
	displayMu.Lock()
	defer displayMu.Unlock()

	conns, err := getConnections(portRanges, *tcpOnly, *udpOnly, !*showAll, *ipv4Only, *ipv6Only, *localFilter, *remoteFilter, *excludeLocal, *excludeRemote, *grepFilter, *excludeGrep)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// 정렬
	sortConnections(conns, *sortBy, *descOrder)
	lastConns = conns

	// 화면 갱신 (첫 실행 또는 터미널 크기 변경 시 전체 화면 지우기)
	cols, rows := getTerminalSize()
	sizeChanged := cols != prevCols || rows != prevRows
	prevCols, prevRows = cols, rows
	cw := calcColWidths(cols)

	if firstRun || sizeChanged {
		clearScreen()
	}
	moveCursor(1, 1)

	if !*noHeader {
		printHeader(*portSpec, *interval, len(conns), !*showAll, cw)
		printTableHeader(cw)
	}

	for _, c := range conns {
		printConnection(c, cw)
		clearLine()
	}

	// Footer
	fmt.Println()
	fmt.Printf("  \033[90mp:pause  q:quit\033[0m")
	clearLine()
	clearToEnd()
}

func printPlainSnapshot(conns []PortInfo) {
	cols, _ := getTerminalSize()
	cw := calcColWidths(cols)
	if !*noHeader {
		printHeader(*portSpec, *interval, len(conns), !*showAll, cw)
		printTableHeader(cw)
	}
	for _, c := range conns {
		printConnection(c, cw)
	}
}

func handleExit() {
	exitOnce.Do(func() {
		disableRawInput()
		restoreConsole()
		fmt.Print("\033[0m")
		if atomic.LoadInt32(&paused) == 0 {
			// 라이브 모드(대체 화면) → 원래 화면으로 복귀 후 스냅샷 출력
			displayMu.Lock()
			snapshot := lastConns
			displayMu.Unlock()
			fmt.Print("\033[?1049l")
			printPlainSnapshot(snapshot)
		}
		fmt.Println("WatchPort terminated.")
		os.Exit(0)
	})
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "WatchPort - 포트 모니터링 도구\n\n")
		fmt.Fprintf(os.Stderr, "Usage: watchport [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  watchport                      # LISTENING 상태의 모든 포트 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -p 80                # 80 포트만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -p 8000-9000         # 8000~9000 범위 포트 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -p 80,443,8080       # 여러 포트 지정\n")
		fmt.Fprintf(os.Stderr, "  watchport -p 3000-4000 -a      # 모든 상태 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -t                   # TCP만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -u                   # UDP만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -s pid               # PID 기준 정렬\n")
		fmt.Fprintf(os.Stderr, "  watchport -4                   # IPv4만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -6                   # IPv6만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -4 -t -p 80          # IPv4 TCP 80포트만\n")
		fmt.Fprintf(os.Stderr, "  watchport -L 127.0.0.1         # Local 127.0.0.1만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -xL \"0.0.0.0,::\"     # Local 0.0.0.0, :: 제외\n")
		fmt.Fprintf(os.Stderr, "  watchport -R 192.168            # Remote 192.168.x.x만 표시\n")
		fmt.Fprintf(os.Stderr, "  watchport -xR \"0.0.0.0,::\"     # Remote 0.0.0.0, :: 제외\n")
		fmt.Fprintf(os.Stderr, "  watchport -g nginx             # 전체 라인에서 nginx 검색 (대소문자 무시)\n")
		fmt.Fprintf(os.Stderr, "  watchport -xg \"0.0.0.0,::\"    # 전체 라인에서 0.0.0.0, :: 포함 제외\n")
		fmt.Fprintf(os.Stderr, "  watchport -n 1                 # 1초마다 갱신\n")
		fmt.Fprintf(os.Stderr, "\nSort options: port, pid, name, proto, status\n")
		fmt.Fprintf(os.Stderr, "\nKeys (while running):\n")
		fmt.Fprintf(os.Stderr, "  p, Space    일시정지/재개\n")
		fmt.Fprintf(os.Stderr, "  q           종료 (마지막 스냅샷 유지)\n")
	}

	flag.Parse()
	startTime = time.Now()

	// 위치 인자로 포트 지정 가능
	if flag.NArg() > 0 && *portSpec == "" {
		*portSpec = flag.Arg(0)
	}

	// 포트 범위 파싱
	portRanges, err := parsePortSpec(*portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// -4 -6 둘 다 지정하면 필터 없음 (모두 표시)
	if *ipv4Only && *ipv6Only {
		*ipv4Only = false
		*ipv6Only = false
	}

	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "Error: 간격은 0보다 커야 합니다")
		os.Exit(1)
	}

	// 콘솔 설정
	setupConsole()
	enableRawInput()
	fmt.Print("\033[?1049h") // 대체 화면 버퍼 진입 (라이브 갱신용)

	// Ctrl+C 처리
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		handleExit()
	}()

	// 키 입력 처리 (p:일시정지/재개, q:종료)
	go func() {
		for {
			key, ok := readKey()
			if !ok {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			switch key {
			case 'p', 'P', ' ':
				if atomic.CompareAndSwapInt32(&paused, 0, 1) {
					// 일시정지: 원래 화면으로 복귀, 전체 스냅샷을 스크롤 가능한 일반 출력으로 인쇄
					displayMu.Lock()
					snapshot := lastConns
					displayMu.Unlock()
					fmt.Print("\033[?1049l")
					printPlainSnapshot(snapshot)
					fmt.Printf("\n  \033[1;43;30m PAUSED \033[0m  \033[90mp:resume  q:quit\033[0m\n")
				} else {
					// 재개: 대체 화면으로 복귀, 라이브 갱신 재시작
					atomic.StoreInt32(&paused, 0)
					fmt.Print("\033[?1049h")
					display(portRanges, true)
				}
			case 'q', 'Q', 3: // q 또는 Ctrl+C
				handleExit()
			}
		}
	}()

	// 첫 실행
	display(portRanges, true)

	// 주기적 갱신
	ticker := time.NewTicker(time.Duration(*interval * float64(time.Second)))
	defer ticker.Stop()

	for range ticker.C {
		if atomic.LoadInt32(&paused) == 0 {
			display(portRanges, false)
		}
	}
}
