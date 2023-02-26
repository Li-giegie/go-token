package go_token

import (
	"crypto/md5"
	go_encdecryption "github.com/Li-giegie/go-encdecryption"
	"github.com/shirou/gopsutil/host"
	"log"
	"math"
	"math/rand"
	"strconv"
	"sync"
	"time"
)
var lock = sync.Mutex{}

var index = rand.Intn(time.Now().Second())
var hostInfo *host.InfoStat

func init(){
	var err error
	rand.Seed(math.MaxInt64)
	info ,err := host.Info()
	if err != nil {
		info = &host.InfoStat{Hostname: err.Error()}
		log.Println("获取HOST Name 失败：",err)
		return
	}
	hostInfo = info
}

func getID() string{
	lock.Lock()
	defer lock.Unlock()
	index ++
	return hostInfo.Hostname + strconv.Itoa(index)
}

func GetMd5(data []byte,key go_encdecryption.Key) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(key)
}
