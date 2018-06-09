package pwdhashservice

import (
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httptest"
    "os"
    "testing"
    "time"
)

//Tests pwdhashservice.getSha512HashString(bytes []byte) string
func TestGetSha512HashString(t *testing.T) {
    t.Run("TestEmpty", func(t *testing.T) {
        hash := getSha512HashString([]byte(""))
        if (hash != "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg_SpIdNs6c5H0NE8XYXysP-DGNKHfuwvY7kxvUdBeoGlODJ6-SfaPg==") {
            t.Logf("Computed Hash: %s", hash)
            t.Fail()
        }
    })
    t.Run("TestSingleWord", func(t *testing.T) {
        hash := getSha512HashString([]byte("mermaids"))
        if (hash != "HS3xurF1BDcLu6hXBIWVNYJdMgPHCFM5YhoBMIykGnJPLKtc0swk2ejymYVvgW5Zx_YfI2irzUIZpo5nMMSeXQ==") {
            t.Logf("Computed Hash: %s", hash)
            t.Fail()
        }
    })
    t.Run("TestWithSpaces", func(t *testing.T) {
        hash := getSha512HashString([]byte("Sphinx of black quartz, judge my vow"))
        if (hash != "hxA90B0zF1pSFAmr-SnTdQPf9sA7zoxveSIdzLxNbLhooGX0vYhtwzPAkmY3pQHOypy4dd5Z0FH-_o1AXDbPNQ==") {
            t.Logf("Computed Hash: %s", hash)
            t.Fail()
        }
    })
    t.Run("TestComplex", func(t *testing.T) {
        hash := getSha512HashString([]byte("cax@qnGic(4tgq)r5"))
        if (hash != "kmYWg5BUcs06Ue2mSJtU0rEDnSuSm9F_kac4k5fB2uwy6n0w6v-oQ1MK4AU2AiC4VqBUnKgLWzTzpByLGPIfoA==") {
            t.Logf("Computed Hash: %s", hash)
            t.Fail()
        }
    })
}

//Tests pwdhashservice.getAverageHashingTimeInMillis(totalHashed int64, totalHashingTime int64) int64
func TestGetAverageHashingTimeInMillis(t *testing.T) {
    t.Run("TestZeroDenominator", func(t *testing.T) {
        getAverageHashingTimeInMillis(0, 5)
    })
    t.Run("TestEasyAverage", func(t *testing.T) {
        average := getAverageHashingTimeInMillis(2, 12)
        if average != 6 {
            t.Logf("Computed average: %d", average)
            t.Fail()
        }
    })
    t.Run("TestRoundedAverage", func(t *testing.T) {
        average := getAverageHashingTimeInMillis(3, 23)
        if average != 7 {
            t.Logf("Computed average: %d", average)
            t.Fail()
        }
    })
}

//Tests pwdhashservice.getJsonStats(totalHashed int64, averageHashingTime int64) string
func TestGetJsonStats(t *testing.T) {
    t.Run("TestJsonConversion", func(t *testing.T) {
        phs := &PwdHashServer{logger : log.New(os.Stdout, "passwordhashingservice: ", log.LstdFlags)}
        json := phs.getJsonStats(30, 2000)
        if json != "{\"average\":2000,\"total\":30}" {
            t.Logf("Converted JSON: %s", json)
            t.Fail()
        }
    })
}

//Tests pwdhashservice.incrementWorkingThreads()
func TestIncrementWorkingThreads(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    prevNumWorkingThreads := phs.threadInfo.numWorkingThreads
    phs.incrementWorkingThreads()
    currNumWorkingThreads := phs.threadInfo.numWorkingThreads
    difference := currNumWorkingThreads - prevNumWorkingThreads
    if difference != 1 {
        t.Logf("The previous number of working threads and current number differ by: %d", difference)
        t.Fail()
    }
}

//Tests pwdhashservice.updateHashingStats(numHashed int64, additionalTime time.Duration)
func TestTotalHashedIncrease(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    prevTotalHashed := phs.hashStats.totalHashed
    phs.updateHashingStats(1, time.Since(time.Now()))
    currTotalHashed := phs.hashStats.totalHashed
    difference := currTotalHashed - prevTotalHashed
    if difference != 1 {
        t.Logf("The previous total hashed and current number differ by: %d", difference)
        t.Fail()
    }
}

//Tests pwdhashservice.updateHashingStats(numHashed int64, additionalTime time.Duration)
func TestTotalHashingTimeIncrease(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    prevTotalHashingTime := phs.hashStats.totalHashingTime
    phs.updateHashingStats(0, 5000 * time.Millisecond)
    currTotalHashingTime := phs.hashStats.totalHashingTime
    difference := currTotalHashingTime - prevTotalHashingTime
    if difference != 5000 {
        t.Logf("The previous total hashing time and current differ by: %d", difference)
        t.Fail()
    }
}

//Tests pwdhashservice.decrementWorkingThreads()
func TestDecrementWorkingThreads(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    prevNumWorkingThreads := phs.threadInfo.numWorkingThreads
    phs.decrementWorkingThreads()
    currNumWorkingThreads := phs.threadInfo.numWorkingThreads
    difference := currNumWorkingThreads - prevNumWorkingThreads
    if difference != -1 {
        t.Logf("The previous number of working threads and current number differ by: %d", difference)
        t.Fail()
    }
}

//Fails the given test if the response from an HTTP handler is found to be incorrect.
func failOnIncorrectResponse(test *testing.T, response *httptest.ResponseRecorder, err error, responseBody string, correctResponseBody string) {
    if (!responseBodyIsCorrect(response, err, string(responseBody), correctResponseBody)) {
        logResponseInfo(test, response, string(responseBody))
        test.Fail()
    }
}

//Helper function for checking response body against the correct response body value.
func responseBodyIsCorrect(response *httptest.ResponseRecorder, err error,  responseBody string, correctResponseBody string) bool {
    if (err != nil || response.Code != 200) || (string(responseBody) != correctResponseBody) {
        return false
    }
    return true
}

//Logs response information.
func logResponseInfo(test *testing.T, response *httptest.ResponseRecorder, responseBody string) {
    test.Logf("Response Code: %d", response.Code)
    test.Logf("Response Body: %s", string(responseBody))
}

//Tests handler returned by pwdhashservice.getHashingHandler() http.HandlerFunc
func TestHashingHandler(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    hashingHandler := phs.getHashingHandler()
    request, _ := http.NewRequest("GET", "/hash?password=dolphins", nil)
    response := httptest.NewRecorder()
    hashingHandler(response, request)
    responseBody, err := ioutil.ReadAll(response.Body)
    correctResponseBody := "UE3OmCOVYuW2ngXQozIyxrWg5_EGaAAUyiDDHN4J6BJC8Iw3Ov3GiBHXiUCUDpMjYd1WkpVtGiRvXQ8mS8ns2A=="
    failOnIncorrectResponse(t, response, err, string(responseBody), correctResponseBody)
}

//Tests handler returned by pwdhashservice.getStatsHandler() http.HandlerFunc
func TestStatsHandler(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    statsHandler := phs.getStatsHandler()
    request, _ := http.NewRequest("GET", "/stats", nil)
    response := httptest.NewRecorder()
    statsHandler(response, request)
    responseBody, err := ioutil.ReadAll(response.Body)
    correctResponseBody := "{\"average\":0,\"total\":0}"
    failOnIncorrectResponse(t, response, err, string(responseBody), correctResponseBody)
}

//Tests handler returned by pwdhashservice.getShutdownHandler() http.HandlerFunc
func TestShutdownHandler(t *testing.T) {
    phs := NewPasswordHashingServer(":8080")
    shutdownHandler := phs.getShutdownHandler()
    request, _ := http.NewRequest("GET", "/shutdown", nil)
    response := httptest.NewRecorder()
    t.Run("TestShutdownInProgress", func(t *testing.T) {
        phs.shutdownInProgress = true
        shutdownHandler(response, request)
        responseBody, err := ioutil.ReadAll(response.Body)
        correctResponseBody := "A server shutdown is already in progress."
        failOnIncorrectResponse(t, response, err, string(responseBody), correctResponseBody)
    })
    t.Run("TestShutdown", func(t *testing.T) {
        phs.shutdownInProgress = false
        shutdownHandler(response, request)
        responseBody, err := ioutil.ReadAll(response.Body)
        correctResponseBody := ""
        failOnIncorrectResponse(t, response, err, string(responseBody), correctResponseBody)
    })
}
