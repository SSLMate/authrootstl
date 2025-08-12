/*
 * Copyright (C) 2025 Opsmate, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization
 */

// List the CT logs recognized by Microsoft
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"software.sslmate.com/src/authrootstl"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix(os.Args[0] + ": ")

	ctl, err := fetchCTL(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	for _, logKey := range ctl.CTLogs {
		keyID := sha256.Sum256(logKey)
		fmt.Println(base64.StdEncoding.EncodeToString(keyID[:]))
	}
}

func fetchCTL(ctx context.Context) (*authrootstl.CTL, error) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Minute))
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, "GET", "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab", nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", request.URL, response.Status)
	}
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", request.URL, err)
	}
	return authrootstl.ParseAuthrootstlCab(bytes.NewReader(bodyBytes))
}
