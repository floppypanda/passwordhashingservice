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
    pwdHashingServer.httpServer = pwdHashingServer.getHttpServer(addr)
    pwdHashingServer.hashStats = &hashingStats{totalHashed : 0, totalHashingTime : 0, totalHashedMutex : sync.Mutex{}, totalHashingTimeMutex : sync.Mutex{}}
    pwdHashingServer.threadInfo = &threadingInfo{numWorkingThreads : 0, numWorkingThreadsMutex : sync.Mutex{}}
    pwdHashingServer.shutdownInProgress = false
    return pwdHashingServer
}

//Builds and returns an HTTP server instance.
func (phs *PwdHashServer) getHttpServer(addr string) *http.Server {
    server := &http.Server {
        Addr:    addr,
        ErrorLog: phs.logger,
    }
    server.Handler = phs.getServerMux()
    return server
}

//Builds and returns the server multiplexer for handlers.
func (phs *PwdHashServer) getServerMux() *http.ServeMux {
    serveMux := http.NewServeMux()
    serveMux.Handle("/hash", phs.getHashingHandler())
    serveMux.Handle("/shutdown", phs.getShutdownHandler())
    serveMux.Handle("/stats", phs.getStatsHandler())
    return serveMux
}

//Builds and returns the hashing handler.
func (phs *PwdHashServer) getHashingHandler() http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if phs.shutdownInProgress {
            return
        }
        phs.incrementWorkingThreads()
        startTime := time.Now()
        time.Sleep(5 * time.Second)
        password := request.URL.Query().Get("password")
        hash := getSha512HashString([]byte(password))
        fmt.Fprintf(responseWriter, "%s", hash)
        phs.incrementTotalHashed()
        elapsedTime := time.Since(startTime)
        phs.increaseTotalHashingTime(elapsedTime)
        phs.logger.Printf("Hashed password \"%s\" into \"%s\".", password, hash)
        phs.decrementWorkingThreads()
    })
}

//Increments the number of working threads.
func (phs *PwdHashServer) incrementWorkingThreads() {
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
func (phs *PwdHashServer) incrementTotalHashed() {
    phs.hashStats.totalHashedMutex.Lock()
    phs.hashStats.totalHashed += 1
    phs.hashStats.totalHashedMutex.Unlock()
}

//Increases the total time spent hashing by the provided duration.
func (phs *PwdHashServer) increaseTotalHashingTime(additionalTime time.Duration) {
    phs.hashStats.totalHashingTimeMutex.Lock()
    phs.hashStats.totalHashingTime += int64(additionalTime/time.Millisecond)
    phs.hashStats.totalHashingTimeMutex.Unlock()
}

//Decrements the number of working threads.
func (phs *PwdHashServer) decrementWorkingThreads() {
    phs.threadInfo.numWorkingThreadsMutex.Lock()
    phs.threadInfo.numWorkingThreads -= 1
    phs.threadInfo.numWorkingThreadsMutex.Unlock()
}

//Builds and returns the shutdown handler.
func (phs *PwdHashServer) getShutdownHandler() http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if !phs.shutdownInProgress {
            phs.shutdownInProgress = true
            phs.logger.Print("Shutting down server...")
            phs.waitForWorkingThreads()
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
func (phs *PwdHashServer) waitForWorkingThreads() {
    for phs.threadInfo.numWorkingThreads > 0 {
    }
}

//Builds and returns the statistics handler.
func (phs *PwdHashServer) getStatsHandler() http.HandlerFunc {
    return http.HandlerFunc(func (responseWriter http.ResponseWriter, request *http.Request) {
        if phs.shutdownInProgress {
            return
        }
        phs.incrementWorkingThreads()
        phs.hashStats.totalHashedMutex.Lock()
        phs.hashStats.totalHashingTimeMutex.Lock()
        jsonStats := phs.getJsonStats(phs.hashStats.totalHashed, getAverageHashingTimeInMillis(phs.hashStats.totalHashed, phs.hashStats.totalHashingTime))
        fmt.Fprintf(responseWriter, jsonStats)
        phs.hashStats.totalHashedMutex.Unlock()
        phs.hashStats.totalHashingTimeMutex.Unlock()
        phs.logger.Printf("Returned the following server statistics: %s", jsonStats)
        phs.decrementWorkingThreads()
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
func (phs *PwdHashServer) getJsonStats(totalHashed int64, averageHashingTime int64) string {
    statsMap := map[string]int64 {"total" : totalHashed, "average" : averageHashingTime}
    jsonStatsMap, err := json.Marshal(statsMap)
    if err != nil {
        phs.logger.Printf("ERROR: Unable to marshal hashing statistics map to JSON.")
    }
    return string(jsonStatsMap)
}

//Starts the server.
func (phs *PwdHashServer) StartServer() {
    phs.logger.Print("Starting server...")
    phs.logger.Fatal(phs.httpServer.ListenAndServe())
}
