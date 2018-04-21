package pwdhashservice

import (
    "context"
    "crypto/sha512"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "sync"
    "time"
)

//Data pertaining to server threading information.
type threadingInfo struct {
    numWorkingThreads int
    numWorkingThreadsMutex sync.Mutex
}

//Data pertaining to server hashing statistics.
type hashingStats struct {
    totalHashed int64
    totalHashingTime int64
    totalHashedMutex sync.Mutex
    totalHashingTimeMutex sync.Mutex
}

//Defines a password hashing server.
type PwdHashServer struct {
    httpServer *http.Server
    logger *log.Logger
    hashStats *hashingStats
    threadInfo *threadingInfo
    shutdownInProgress bool
}

//Builds and returns a server instance.
func NewPasswordHashingServer(addr string) *PwdHashServer {
    pwdHashingServer := &PwdHashServer{}
    pwdHashingServer.logger = log.New(os.Stdout, "passwordhashingservice: ", log.LstdFlags)
    pwdHashingServer.httpServer = getHttpServer(pwdHashingServer, addr)
    pwdHashingServer.hashStats = &hashingStats{totalHashed : 0, totalHashingTime : 0, totalHashedMutex : sync.Mutex{}, totalHashingTimeMutex : sync.Mutex{}}
    pwdHashingServer.threadInfo = &threadingInfo{numWorkingThreads : 0, numWorkingThreadsMutex : sync.Mutex{}}
    pwdHashingServer.shutdownInProgress = false
    return pwdHashingServer
}

//Builds and returns an HTTP server instance.
func getHttpServer(phs *PwdHashServer, addr string) *http.Server {
    server := &http.Server {
        Addr:    addr,
        ErrorLog: phs.logger,
    }
    server.Handler = getServerMux(phs)
    return server
}

//Builds and returns the server multiplexer for handlers.
func getServerMux(phs *PwdHashServer) *http.ServeMux {
    serveMux := http.NewServeMux()
    serveMux.Handle("/hash", getHashingHandler(phs))
    serveMux.Handle("/shutdown", getShutdownHandler(phs))
    serveMux.Handle("/stats", getStatsHandler(phs))
    return serveMux
}

//Builds and returns the hashing handler.
func getHashingHandler(phs *PwdHashServer) http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if phs.shutdownInProgress {
            return
        }
        incrementWorkingThreads(phs)
        startTime := time.Now()
        time.Sleep(5 * time.Second)
        password := request.URL.Query().Get("password")
        fmt.Fprintf(responseWriter, "%s", getSha512HashString([]byte(password)))
        incrementTotalHashed(phs)
        elapsedTime := time.Since(startTime)
        increaseTotalHashingTime(phs, elapsedTime)
        decrementWorkingThreads(phs)
    })
}

//Increments the number of working threads.
func incrementWorkingThreads(phs *PwdHashServer) {
    phs.threadInfo.numWorkingThreadsMutex.Lock()
    phs.threadInfo.numWorkingThreads += 1
    phs.threadInfo.numWorkingThreadsMutex.Unlock()
}

//Computes a hash from an array of bytes using SHA-512.
func getSha512HashString(bytes []byte) string {
    hasher := sha512.New()
    hasher.Write(bytes)
    sha512Hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
    return sha512Hash
}

//Increments the count of total hashings.
func incrementTotalHashed(phs *PwdHashServer) {
    phs.hashStats.totalHashedMutex.Lock()
    phs.hashStats.totalHashed += 1
    phs.hashStats.totalHashedMutex.Unlock()
}

//Increases the total time spent hashing by the provided duration.
func increaseTotalHashingTime(phs *PwdHashServer, additionalTime time.Duration) {
    phs.hashStats.totalHashingTimeMutex.Lock()
    phs.hashStats.totalHashingTime += int64(additionalTime/time.Millisecond)
    phs.hashStats.totalHashingTimeMutex.Unlock()
}

//Decrements the number of working threads.
func decrementWorkingThreads(phs *PwdHashServer) {
    phs.threadInfo.numWorkingThreadsMutex.Lock()
    phs.threadInfo.numWorkingThreads -= 1
    phs.threadInfo.numWorkingThreadsMutex.Unlock()
}

//Builds and returns the shutdown handler.
func getShutdownHandler(phs *PwdHashServer) http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if !phs.shutdownInProgress {
            phs.shutdownInProgress = true
            waitForWorkingThreads(phs)
            if err := phs.httpServer.Shutdown(context.Background()); err != nil {
                fmt.Fprint(responseWriter, "Unable to shutdown server.")
                phs.logger.Fatalf("ERROR: Unable to gracefully shutdown server:\n %v\n", err)
            }
        } else {
            fmt.Fprintf(responseWriter, "A server shutdown is already in progress.")
        }
    })
}

//Waits for threads corresponding to in progress connections to complete.
func waitForWorkingThreads(phs *PwdHashServer) {
    for phs.threadInfo.numWorkingThreads > 0 {
    }
}

//Builds and returns the statistics handler.
func getStatsHandler(phs *PwdHashServer) http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if phs.shutdownInProgress {
            return
        }
        incrementWorkingThreads(phs)
        phs.hashStats.totalHashedMutex.Lock()
        phs.hashStats.totalHashingTimeMutex.Lock()
        fmt.Fprintf(responseWriter, getJsonStats(phs, phs.hashStats.totalHashed, getAverageHashingTimeInMillis(phs.hashStats.totalHashed, phs.hashStats.totalHashingTime)))
        phs.hashStats.totalHashedMutex.Unlock()
        phs.hashStats.totalHashingTimeMutex.Unlock()
        decrementWorkingThreads(phs)
    })
}

//Computes the average time elapsed during password hashing.
func getAverageHashingTimeInMillis(totalHashed int64, totalHashingTime int64) int64 {
    if (totalHashed == 0) {
        return 0
    }
    return totalHashingTime/totalHashed
}

//Creates a string in JSON format using server statistics.
func getJsonStats(phs *PwdHashServer, totalHashed int64, averageHashingTime int64) string {
    statsMap := map[string]int64 {"total" : totalHashed, "average" : averageHashingTime}
    jsonStatsMap, err := json.Marshal(statsMap)
    if err != nil {
        phs.logger.Printf("ERROR: Unable to marshal hashing statistics map to JSON.")
    }
    return string(jsonStatsMap)
}

//Starts the server.
func StartServer(pwdHashingServer *PwdHashServer) {
    log.Fatal(pwdHashingServer.httpServer.ListenAndServe())
}
