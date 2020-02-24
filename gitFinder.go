package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"gopkg.in/gookit/color.v1"

	"bytes"
	"compress/zlib"
	"crypto/tls"
	"regexp"
	"sync"

	"golang.org/x/net/proxy"

	//_ "net/http/pprof"
	//"./libgogitdumper"
	"github.com/c-sto/gogitdumper/libgogitdumper"
)

var version = "0.5.2"

var commonrefs = []string{
	"", //check for indexing
	"FETCH_HEAD", "HEAD", "ORIG_HEAD",
	"config", "info/refs", "logs/HEAD", "logs/refs/heads/master",
	"logs/refs/remotes/origin/HEAD", "logs/refs/remotes/origin/master",
	"logs/refs/stash", "packed-refs", "refs/heads/master",
	"refs/remotes/origin/HEAD", "refs/remotes/origin/master", "refs/stash",
}

var commonfiles = []string{
	"COMMIT_EDITMSG", "description", "hooks/applypatch-msg.sample", "hooks/applypatch-msg.sample",
	"hooks/applypatch-msg.sample", "hooks/commit-msg.sample", "hooks/post-commit.sample",
	"hooks/post-receive.sample", "hooks/post-update.sample", "hooks/pre-applypatch.sample",
	"hooks/pre-commit.sample", "hooks/pre-push.sample", "hooks/pre-rebase.sample",
	"hooks/pre-receive.sample", "hooks/prepare-commit-msg.sample", "hooks/update.sample",
	"info/exclude",
	//these are obtained individually to be parsed for goodies
	//"objects/info/packs",
	//"index",
}

var tested libgogitdumper.ThreadSafeSet
var urlCfg string
var localpath string

var fileCount uint64
var byteCount uint64

var client *http.Client

func printHeader() {
	color.Red.Println("            _ _           _       _       _     ")
	color.Red.Println("           (_) |         | |     | |     | |    ")
	color.Red.Println("  _____   ___| | ___ __ _| |_ ___| | __ _| |__  ")
	color.Red.Println(" / _ \\ \\ / / | |/ __/ _` | __/ __| |/ _` | '_ \\ ")
	color.White.Println("|  __/\\ V /| | | (_| (_| | |_\\__ \\ | (_| | |_) |")
	color.White.Println(" \\___| \\_/ |_|_|\\___\\__,_|\\__|___/_|\\__,_|_.__/ \n")
	color.Red.Println("   Domain .git/HEAD Finder\n\n\n")
}

func SetConsoleTitle(title string) (int, error) {
	handle, err := syscall.LoadLibrary("Kernel32.dll")
	if err != nil {
		return 0, err
	}
	defer syscall.FreeLibrary(handle)
	proc, err := syscall.GetProcAddress(handle, "SetConsoleTitleW")
	if err != nil {
		return 0, err
	}
	r, _, err := syscall.Syscall(proc, 1, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))), 0, 0)
	return int(r), err
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

var reader = bufio.NewReader(os.Stdin)

func main() {

	if runtime.GOOS == "windows" {
		SetConsoleTitle(".git/HEAD Finder")
	}
	printHeader()

	color.Green.Print("Website Domain List ( format : domain.xxx separate by newline ) : ")
	spotifyFilePath, _ := reader.ReadString('\n')
	spotifyFilePath = strings.TrimSuffix(spotifyFilePath, "\n")
	spotifyFilePath = strings.TrimSuffix(spotifyFilePath, "\r")

	lines, err := readLines(spotifyFilePath)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}

	for _, element := range lines {
		if len(element) > 1 {
			CheckGitHead(element)
			time.Sleep(time.Millisecond * 300)
		}
	}

	reader.ReadString('\n')
}

//Checking Spotify Function
func CheckGitHead(domain string) {

	//adding the Transport object to the http Client
	clientCheckGit := &http.Client{}

	request, err := http.NewRequest("GET", domain+"/.git/HEAD", nil)
	if err != nil {
		log.Print("Error New Request")
		log.Println(err)
	}

	request.Header.Add("Accept-Encoding", "gzip, deflate, sdch, br")
	request.Header.Add("Accept-Language", "it-IT,it;q=0.8,en-US;q=0.6,en;q=0.4")
	request.Header.Add("Upgrade-Insecure-Requests", "1")
	request.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")
	request.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Header.Add("Cache-Control", "max-age=0")
	request.Header.Add("Connection", "keep-alive")

	response, err := clientCheckGit.Do(request)

	if err != nil {
		log.Print("Error Do Request")
		log.Println(err)
	}

	data, err := ioutil.ReadAll(response.Body)

	if strings.Contains(string(data), "ref:") == true {
		color.Green.Println(domain + " : .git/HEAD found.")
		f, err := os.OpenFile("githeadfound.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		if _, err := fmt.Fprintln(f, domain+" : .git/HEAD found."); err != nil {
			log.Println(err)
		}

		cfg := libgogitdumper.Config{}
		var SSLIgnore bool

		cfg.Url = domain + "/.git/"

		httpTransport := &http.Transport{}
		client = &http.Client{Transport: httpTransport}

		//skip ssl errors if requested to
		httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: SSLIgnore}
		//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: SSLIgnore}

		//user a proxy if requested to
		if cfg.ProxyAddr != "" {
			fmt.Println("Proxy set to: ", cfg.ProxyAddr)
			dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, nil, proxy.Direct)
			if err != nil {
				os.Exit(1)
			}
			httpTransport.Dial = dialer.Dial
		}
		cfg.Threads = 10
		workers := cfg.Threads
		tested = libgogitdumper.ThreadSafeSet{}.Init()

		wg := &sync.WaitGroup{} //this is way overcomplicate, there is probably a better way...

		urlCfg = cfg.Url

		u, err := url.Parse(domain)
		if err != nil {
			log.Fatal(err)
		}
		parts := strings.Split(u.Hostname(), ".")
		folderDest := parts[len(parts)-2]

		localpath = folderDest + "/.git/"

		//setting the chan size to bigger than the number of workers to avoid deadlocks on high worker counts
		getqueue := make(chan string, workers*2)
		newfilequeue := make(chan string, workers*2)
		writefileChan := make(chan libgogitdumper.Writeme, workers*2)

		go libgogitdumper.LocalWriter(writefileChan, localpath, &fileCount, &byteCount, wg) //writes out the downloaded files

		//takes any new objects identified, and checks to see if already downloaded. will add new files to the queue if unique.
		go adderWorker(getqueue, newfilequeue, wg)

		isListingEnabled, rawListing := testListing(urlCfg)

		if isListingEnabled {
			fmt.Println("Indexing identified, recursively downloading repo directory...")
			for x := 0; x < workers; x++ {
				go ListingGetWorker(getqueue, newfilequeue, writefileChan, wg)
			}
			for _, x := range parseListing(rawListing) {
				wg.Add(1)
				newfilequeue <- urlCfg + x
			}
		} else {
			//downloader bois
			for x := 0; x < workers; x++ {
				go GetWorker(getqueue, newfilequeue, writefileChan, wg)
			}

			//get the index file, parse it for files and whatnot
			if cfg.IndexBypass {
				wg.Add(1)
				newfilequeue <- urlCfg + "index"
			} else if cfg.IndexLocation != "" {
				indexfile, err := ioutil.ReadFile(cfg.IndexLocation)
				if err != nil {
					panic("Could not read index file: " + err.Error())
				}
				err = getIndex(indexfile, newfilequeue, writefileChan, wg)
				if err != nil {
					panic(err)
				}
			} else {
				indexfile, err := libgogitdumper.GetThing(urlCfg+"index", client)
				if err != nil {
					panic(err)
				}

				err = getIndex(indexfile, newfilequeue, writefileChan, wg)
				if err != nil {
					panic(err)
				}
			}

			//get the packs (if any exist) and parse them out too
			getPacks(newfilequeue, writefileChan, wg)

			//get all the common things that contain refs
			for _, x := range commonrefs {
				wg.Add(1)
				newfilequeue <- urlCfg + x
			}

			//get all the common files that may be important I guess?
			for _, x := range commonfiles {
				wg.Add(1)
				newfilequeue <- urlCfg + x
			}
		}

		wg.Wait() //this is more accurate, but difficult to manage and makes the code all gross(er)

		//keeping this here for legacy - it should always break out
		for {
			if len(getqueue) == 0 && len(newfilequeue) == 0 {
				break
			}
			fmt.Println("ERROR! WG CALCULATION WRONG")
			time.Sleep(time.Second * 2)
		}
		fmt.Printf("Wrote %d files and %d bytes\n\n\n", fileCount, byteCount)

	} else {
		color.Green.Print(domain + " : .git/HEAD not found.")
	}
}

func parseListing(page []byte) []string {
	var r []string
	baseDirRe := regexp.MustCompile("Directory listing for /.git/.*<")
	baseDirByt := baseDirRe.Find(page)
	baseDirStr := string(baseDirByt[28 : len(baseDirByt)-1])
	listingRe := regexp.MustCompile("href=[\"'](.*?)[\"']")
	match := listingRe.FindAll(page, -1)
	for _, x := range match {
		r = append(r, baseDirStr+string(x[6:len(x)-1]))
	}
	return r
}

func getPacks(newfilequeue chan string, writefileChan chan libgogitdumper.Writeme, wg *sync.WaitGroup) {
	//todo: parse packfiles for new objects and whatnot
	//get packfiles from objects/info/packs

	packfile, err := libgogitdumper.GetThing(urlCfg+"objects/info/packs", client)
	if err != nil {
		//handle error?
	}
	fmt.Println("Downloaded: ", urlCfg+"objects/info/packs")

	d := libgogitdumper.Writeme{}
	d.LocalFilePath = localpath + string(os.PathSeparator) + "objects" + string(os.PathSeparator) + "info" + string(os.PathSeparator) + "packs"
	d.Filecontents = packfile

	wg.Add(1)
	writefileChan <- d

	if len(packfile) > 0 {
		//this is not how packfiles work. Worst case is we accidentally download some packfiles,
		//but as the sha1 is based on the last 20 bytes (or something like that), not sure how to do this blindly
		sha1re := regexp.MustCompile("[0-9a-fA-F]{40}")
		match := sha1re.FindAll(packfile, -1) //doing dumb regex look for sha1's in packfiles, I don't think this is how it works tbh
		for _, x := range match {

			wg.Add(1)
			newfilequeue <- urlCfg + "objects/pack/pack-" + string(x) + ".idx"
			wg.Add(1)
			newfilequeue <- urlCfg + "objects/pack/pack-" + string(x) + ".pack"
		}

	}
}

func getIndex(indexfile []byte, newfileChan chan string, localfileChan chan libgogitdumper.Writeme, wg *sync.WaitGroup) error {

	fmt.Println("Downloaded: ", urlCfg+"index")

	d := libgogitdumper.Writeme{}
	d.LocalFilePath = localpath + string(os.PathSeparator) + "index"
	d.Filecontents = indexfile

	wg.Add(1)
	localfileChan <- d

	parsed, err := libgogitdumper.ParseIndexFile(indexfile)
	if err != nil {
		//deal with parsing error X_X (not blocking for now)
		return nil
	}

	for _, x := range parsed.Entries {
		wg.Add(1)
		newfileChan <- urlCfg + "objects/" + string(x.Sha1[0:2]) + "/" + string(x.Sha1[2:])
	}

	return err

}

func testListing(urlCfg string) (bool, []byte) {
	resp, err := libgogitdumper.GetThing(urlCfg, client)
	if err != nil {
		fmt.Println(err, "\nError during indexing test")
		return false, nil
		//todo: handle err better
	}

	if strings.Contains(string(resp), "<title>Directory listing for ") {
		return true, resp
	}
	return false, nil
}

func ListingGetWorker(c chan string, c2 chan string, localFileWriteChan chan libgogitdumper.Writeme, wg *sync.WaitGroup) {
	for {
		path := <-c
		//check for directory
		if string(path[len(path)-1]) == "/" {
			//don't bother downloading this file to save locally, but parse it for MORE files!
			isActually, listingContent := testListing(path)
			if isActually {
				fmt.Println("Found Directory: ", path)
				for _, x := range parseListing(listingContent) {
					wg.Add(1) //to be processed by adderworker
					c2 <- urlCfg + x
				}
			}

		} else {
			//not a directory, download the file and write it as per normal
			resp, err := libgogitdumper.GetThing(path, client)
			if err != nil {
				fmt.Println(err, path)
				wg.Done()
				continue //todo: handle err better
			}
			fmt.Println("Downloaded: ", path)
			//write to local path
			d := libgogitdumper.Writeme{}
			d.LocalFilePath = localpath + string(os.PathSeparator) + path[len(urlCfg):]
			d.Filecontents = resp

			wg.Add(1) //to be processed by localwriterworker
			localFileWriteChan <- d
		}
		wg.Done() //finished getting the new thing
	}
}

func GetWorker(c chan string, c2 chan string, localFileWriteChan chan libgogitdumper.Writeme, wg *sync.WaitGroup) {
	sha1re := regexp.MustCompile("[0-9a-fA-F]{40}")
	refre := regexp.MustCompile(`(refs(/[a-zA-Z0-9\-\.\_\*]+)+)`)
	for {
		path := <-c
		resp, err := libgogitdumper.GetThing(path, client)
		if err != nil {
			fmt.Println(err, path)
			wg.Done()
			continue //todo: handle err better
		}
		fmt.Println("Downloaded: ", path)
		//write to local path
		d := libgogitdumper.Writeme{}
		d.LocalFilePath = localpath + string(os.PathSeparator) + path[len(urlCfg):]
		d.Filecontents = resp

		wg.Add(1)
		localFileWriteChan <- d

		//check if we can zlib decompress it
		zl := bytes.NewReader(resp)
		r, err := zlib.NewReader(zl)
		if err == nil {
			buf := new(bytes.Buffer)
			buf.ReadFrom(r)
			resp = buf.Bytes()
			r.Close()
		}

		//check for any sha1 objects in the thing
		match := sha1re.FindAll(resp, -1)
		for _, x := range match {
			//add sha1's to line
			wg.Add(1)
			c2 <- urlCfg + "objects/" + string(x[0:2]) + "/" + string(x[2:])

		}

		//check for ref paths in the thing
		match = refre.FindAll(resp, -1)
		for _, x := range match {
			if string(x[len(x)-1]) == "*" {
				continue
			}
			wg.Add(1)
			c2 <- urlCfg + string(x)
			wg.Add(1)
			c2 <- urlCfg + "logs/" + string(x)
		}
		wg.Done()

	}
}

func adderWorker(getChan chan string, potentialChan chan string, wg *sync.WaitGroup) {
	for {
		x := <-potentialChan
		if !tested.HasValue(x) {
			tested.Add(x)
			wg.Add(1) //signal that we have some more stuff to do (added to the 'get' chan)
			select {
			case getChan <- x:
				//do nothing (this should avoid spinnign up infinity goroutines, and instead only spin up infinity/2)
			default:
				//do it later
				go func() { getChan <- x }() //this is way less gross than the other blocking thing
			}

		}
		wg.Done() //we finished processing the potentially new thing
	}

}
